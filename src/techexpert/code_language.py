"""A JSON capability language interpreted from AST, never Python bytecode execution."""
import ast
import math
import re

from .code_values import CodeError,MAX_INT,MAX_ITEMS,MAX_STRING,MAX_VALUE_BYTES,bounded,copy_json,number

FUNCTIONS={'api','len','get','keys','values','sum','min','max','abs','round','sorted','range','str','int','float','bool'}
_NODES={ast.Module,ast.Assign,ast.AugAssign,ast.Expr,ast.Return,ast.If,ast.For,ast.While,ast.Break,ast.Continue,ast.Pass,
    ast.Constant,ast.Name,ast.Load,ast.Store,ast.List,ast.Tuple,ast.Dict,ast.Subscript,ast.Slice,
    ast.BinOp,ast.UnaryOp,ast.BoolOp,ast.Compare,ast.IfExp,ast.Call,ast.keyword,
    ast.ListComp,ast.DictComp,ast.GeneratorExp,ast.comprehension,
    ast.Add,ast.Sub,ast.Mult,ast.Div,ast.FloorDiv,ast.Mod,ast.UAdd,ast.USub,ast.Not,ast.And,ast.Or,
    ast.Eq,ast.NotEq,ast.Lt,ast.LtE,ast.Gt,ast.GtE,ast.In,ast.NotIn,ast.Is,ast.IsNot}


def identifier(name):
    if not isinstance(name,str) or not re.fullmatch('[A-Za-z][A-Za-z0-9_]{0,63}',name) or name in FUNCTIONS:
        raise CodeError('forbidden_syntax','Program variable name is reserved or unsupported.')
    return name


def parse_program(source):
    if not isinstance(source,str) or not source.strip():raise CodeError('invalid_program','A nonempty bounded program is required.')
    try:
        if len(source.encode('utf-8'))>65536:raise CodeError('program_limit','Program exceeds 64 KiB UTF-8.')
        tree=ast.parse(source,filename='<bounded-code>',mode='exec')
    except (SyntaxError,UnicodeError,RecursionError,ValueError) as exc:
        if isinstance(exc,CodeError):raise
        raise CodeError('invalid_program','The source is not valid in the bounded language.') from exc
    count=0
    def visit(node,parent=None,depth=0,loops=0):
        nonlocal count
        count+=1
        if count>4096 or depth>64:raise CodeError('program_limit','Program AST exceeds structural limits.')
        if type(node) not in _NODES:raise CodeError('forbidden_syntax','Unsupported program syntax: '+type(node).__name__)
        if isinstance(node,ast.Name):
            if node.id in FUNCTIONS:
                if not isinstance(parent,ast.Call) or parent.func is not node:raise CodeError('forbidden_syntax','Functions cannot be used as program values.')
            else:identifier(node.id)
        if isinstance(node,ast.Constant):bounded(node.value,max_bytes=MAX_VALUE_BYTES)
        if isinstance(node,ast.Call):
            if not isinstance(node.func,ast.Name) or node.func.id not in FUNCTIONS:raise CodeError('forbidden_syntax','Only named approved functions can be called.')
            names=[kw.arg for kw in node.keywords]
            if None in names or len(set(names))!=len(names):raise CodeError('forbidden_syntax','Expanded or duplicate keyword arguments are unavailable.')
        if isinstance(node,ast.Dict) and any(key is None for key in node.keys):raise CodeError('forbidden_syntax','Dictionary unpacking is unavailable.')
        if isinstance(node,ast.comprehension) and node.is_async:raise CodeError('forbidden_syntax','Async comprehensions are unavailable.')
        if isinstance(node,(ast.For,ast.While)) and node.orelse:raise CodeError('forbidden_syntax','Loop else blocks are unavailable in this profile.')
        if isinstance(node,(ast.Break,ast.Continue)) and not loops:raise CodeError('forbidden_syntax','Loop control requires a loop.')
        for child in ast.iter_child_nodes(node):visit(child,node,depth+1,loops+int(isinstance(node,(ast.For,ast.While))))
    visit(tree)
    return tree


class _Return(Exception):
    def __init__(self,value):self.value=value
class _Break(Exception):pass
class _Continue(Exception):pass


class Machine:
    def __init__(self,tree,bindings,api,*,max_steps=200000,max_value_bytes=MAX_VALUE_BYTES,stop=None):
        if type(max_steps) is not int or not 1<=max_steps<=2000000:raise CodeError('invalid_program','Invalid program step budget.')
        if type(max_value_bytes) is not int or not 16384<=max_value_bytes<=MAX_VALUE_BYTES:raise CodeError('invalid_program','Invalid program value budget.')
        self.tree=tree;self.api=api;self.stop=stop;self.max_steps=max_steps;self.max_value_bytes=max_value_bytes
        self.env=copy_json(bindings,max_bytes=16384)
        if type(self.env) is not dict or len(self.env)>64:raise CodeError('invalid_program','Bindings must be a bounded object.')
        for name in self.env:identifier(name)
        self.metrics=dict(steps=0,validated_value_bytes=0)

    def tick(self,count=1):
        old=self.metrics['steps'];self.metrics['steps']+=count
        if self.metrics['steps']>self.max_steps:raise CodeError('step_limit','Program step budget reached.')
        if self.stop and (old//32!=self.metrics['steps']//32 or old==0):
            reason=self.stop()
            if reason:raise CodeError('cancelled' if reason=='cancelled' else 'timeout','Program execution was stopped by its owned boundary.')

    def check(self,value):
        size=bounded(value,max_bytes=self.max_value_bytes);self.metrics['validated_value_bytes']+=size['bytes']
        return value

    def run(self):
        try:self.block(self.tree.body)
        except _Return as result:return self.check(result.value)
        raise CodeError('invalid_program','The program must return a JSON value.')

    def block(self,body):
        for node in body:self.statement(node)

    def assign(self,target,value):
        self.tick()
        if isinstance(target,ast.Name):
            identifier(target.id)
            if target.id not in self.env and len(self.env)>=64:raise CodeError('value_limit','Program variable limit reached.')
            self.env[target.id]=self.check(value);return
        if isinstance(target,(ast.List,ast.Tuple)):
            if type(value) is not list or len(value)!=len(target.elts):raise CodeError('invalid_value','Destructuring requires a matching list.')
            for child,item in zip(target.elts,value):self.assign(child,item)
            return
        if isinstance(target,ast.Subscript):
            container=self.expression(target.value);key=self.index(target.slice)
            if type(container) is dict:
                if type(key) is not str:raise CodeError('invalid_value','Dictionary keys must be strings.')
            elif type(container) is list:
                if type(key) is not int:raise CodeError('invalid_value','List assignment requires an integer index.')
            else:raise CodeError('invalid_value','Only JSON collections can be assigned by index.')
            try:container[key]=value
            except (IndexError,KeyError,TypeError) as exc:raise CodeError('invalid_value','Invalid assignment index.') from exc
            self.check(container);return
        raise CodeError('forbidden_syntax','Unsupported assignment target.')

    def statement(self,node):
        self.tick()
        if isinstance(node,ast.Assign):
            value=self.expression(node.value)
            for target in node.targets:self.assign(target,value)
        elif isinstance(node,ast.AugAssign):self.assign(node.target,self.binary(node.op,self.expression(node.target),self.expression(node.value)))
        elif isinstance(node,ast.Expr):self.expression(node.value)
        elif isinstance(node,ast.Return):raise _Return(self.expression(node.value) if node.value is not None else None)
        elif isinstance(node,ast.If):self.block(node.body if self.expression(node.test) else node.orelse)
        elif isinstance(node,ast.For):
            items=self.iterable(self.expression(node.iter))
            for item in items:
                self.tick();self.assign(node.target,item)
                try:self.block(node.body)
                except _Continue:continue
                except _Break:break
        elif isinstance(node,ast.While):
            while self.expression(node.test):
                self.tick()
                try:self.block(node.body)
                except _Continue:continue
                except _Break:break
        elif isinstance(node,ast.Break):raise _Break()
        elif isinstance(node,ast.Continue):raise _Continue()
        elif isinstance(node,ast.Pass):pass
        else:raise CodeError('forbidden_syntax','Unsupported statement.')

    def iterable(self,value):
        if type(value) not in (list,dict,str) or len(value)>MAX_ITEMS:raise CodeError('invalid_value','A bounded JSON collection is required.')
        return list(value)

    def index(self,node):
        if isinstance(node,ast.Slice):
            values=[self.expression(x) if x else None for x in (node.lower,node.upper,node.step)]
            if any(x is not None and type(x) is not int for x in values) or values[2]==0:raise CodeError('invalid_value','Invalid bounded slice.')
            return slice(*values)
        return self.expression(node)

    def expression(self,node):
        self.tick()
        if isinstance(node,ast.Constant):return node.value
        if isinstance(node,ast.Name):
            if node.id not in self.env:raise CodeError('invalid_value','Program variable is not defined.')
            return self.env[node.id]
        if isinstance(node,(ast.List,ast.Tuple)):return self.check([self.expression(x) for x in node.elts])
        if isinstance(node,ast.Dict):return self.check({self.expression(k):self.expression(v) for k,v in zip(node.keys,node.values)})
        if isinstance(node,ast.Subscript):
            value=self.expression(node.value);key=self.index(node.slice)
            if type(value) is dict and type(key) is not str:raise CodeError('invalid_value','Dictionary lookup requires a string key.')
            if type(value) in (list,str) and not (type(key) is int or isinstance(key,slice)):raise CodeError('invalid_value','Sequence lookup requires an integer or slice.')
            if type(value) not in (dict,list,str):raise CodeError('invalid_value','Only JSON collections support lookup.')
            try:return value[key]
            except (KeyError,IndexError,TypeError) as exc:raise CodeError('invalid_value','Program lookup is unavailable.') from exc
        if isinstance(node,ast.BinOp):return self.binary(node.op,self.expression(node.left),self.expression(node.right))
        if isinstance(node,ast.UnaryOp):
            value=self.expression(node.operand)
            if isinstance(node.op,ast.Not):return not value
            return number(-number(value) if isinstance(node.op,ast.USub) else number(value))
        if isinstance(node,ast.BoolOp):
            value=self.expression(node.values[0])
            for child in node.values[1:]:
                if isinstance(node.op,ast.And) and not value or isinstance(node.op,ast.Or) and value:break
                value=self.expression(child)
            return value
        if isinstance(node,ast.Compare):
            left=self.expression(node.left)
            for op,child in zip(node.ops,node.comparators):
                right=self.expression(child)
                if not self.compare(op,left,right):return False
                left=right
            return True
        if isinstance(node,ast.IfExp):return self.expression(node.body if self.expression(node.test) else node.orelse)
        if isinstance(node,ast.Call):
            args=[self.expression(x) for x in node.args];kwargs={x.arg:self.expression(x.value) for x in node.keywords}
            return self.check(self.function(node.func.id,args,kwargs))
        if isinstance(node,(ast.ListComp,ast.DictComp,ast.GeneratorExp)):return self.comprehension(node)
        raise CodeError('forbidden_syntax','Unsupported expression.')

    def comprehension(self,node):
        old=dict(self.env);result={} if isinstance(node,ast.DictComp) else []
        def advance(index):
            self.tick()
            if index==len(node.generators):
                if type(result) is dict:
                    key=self.expression(node.key)
                    if type(key) is not str:raise CodeError('invalid_value','Dictionary keys must be strings.')
                    result[key]=self.expression(node.value)
                else:result.append(self.expression(node.elt))
                if len(result)>MAX_ITEMS:raise CodeError('value_limit','Comprehension exceeds item limit.')
                return
            generator=node.generators[index]
            for item in self.iterable(self.expression(generator.iter)):
                self.assign(generator.target,item)
                if all(self.expression(x) for x in generator.ifs):advance(index+1)
        try:advance(0);return self.check(result)
        finally:self.env=old

    def binary(self,op,left,right):
        if isinstance(op,ast.Add) and type(left) is type(right) and type(left) in (str,list):
            high=MAX_STRING if type(left) is str else MAX_ITEMS
            if len(left)+len(right)>high:raise CodeError('value_limit','Concatenation exceeds value limit.')
            return self.check(left+right)
        if isinstance(op,ast.Mult) and (type(left) in (str,list) and type(right) is int or type(right) in (str,list) and type(left) is int):
            value,count=(left,right) if type(left) in (str,list) else (right,left)
            high=MAX_STRING if type(value) is str else MAX_ITEMS
            if len(value)*max(0,count)>high:raise CodeError('value_limit','Repetition exceeds value limit.')
            return self.check(value*max(0,count))
        number(left);number(right)
        try:
            if isinstance(op,ast.Add):value=left+right
            elif isinstance(op,ast.Sub):value=left-right
            elif isinstance(op,ast.Mult):value=left*right
            elif isinstance(op,ast.Div):value=left/right
            elif isinstance(op,ast.FloorDiv):value=left//right
            elif isinstance(op,ast.Mod):value=left%right
            else:raise CodeError('forbidden_syntax','Unsupported arithmetic operator.')
        except (ArithmeticError,ValueError) as exc:raise CodeError('invalid_value','Invalid finite arithmetic.') from exc
        return number(value)

    def compare(self,op,left,right):
        if isinstance(op,(ast.Is,ast.IsNot)):
            if left is not None and right is not None:raise CodeError('invalid_value','Identity comparisons are available only for unknown (None).')
            return (left is right) if isinstance(op,ast.Is) else (left is not right)
        if isinstance(op,ast.Eq):return left==right
        if isinstance(op,ast.NotEq):return left!=right
        if isinstance(op,(ast.In,ast.NotIn)):
            if type(right) not in (str,list,dict):raise CodeError('invalid_value','Membership requires a JSON collection.')
            self.tick(len(right))
            try:value=left in right
            except TypeError as exc:raise CodeError('invalid_value','Invalid membership value.') from exc
            return value if isinstance(op,ast.In) else not value
        if not (type(left) is str and type(right) is str):number(left);number(right)
        if isinstance(op,ast.Lt):return left<right
        if isinstance(op,ast.LtE):return left<=right
        if isinstance(op,ast.Gt):return left>right
        if isinstance(op,ast.GtE):return left>=right
        raise CodeError('forbidden_syntax','Unsupported comparison.')

    def function(self,name,args,kwargs):
        self.tick()
        if name=='api':
            if kwargs:
                if args or set(kwargs)!={'operation','arguments'}:raise CodeError('invalid_value','api requires operation and arguments.')
                args=[kwargs['operation'],kwargs['arguments']]
            if len(args)!=2 or type(args[0]) is not str or type(args[1]) is not dict:raise CodeError('invalid_value','api requires a name and JSON argument object.')
            return copy_json(self.api(args[0],args[1]),max_bytes=self.max_value_bytes)
        if kwargs and not (name=='sorted' and set(kwargs)<={'reverse'} or name=='round' and set(kwargs)<={'ndigits'}):
            raise CodeError('invalid_value','Unsupported function keywords.')
        try:
            if name=='len' and len(args)==1 and type(args[0]) in (list,dict,str):return len(args[0])
            if name=='get' and len(args) in (2,3) and type(args[0]) is dict and type(args[1]) is str:return args[0].get(args[1],args[2] if len(args)==3 else None)
            if name in ('keys','values') and len(args)==1 and type(args[0]) is dict:return list(args[0].keys() if name=='keys' else args[0].values())
            if name in ('sum','min','max','sorted') and len(args)==1:
                values=self.iterable(args[0]);self.tick(len(values))
                if name in ('sum','min','max'):
                    for value in values:number(value)
                    return number({'sum':sum,'min':min,'max':max}[name](values))
                reverse=kwargs.get('reverse',False)
                if type(reverse) is not bool:raise CodeError('invalid_value','sorted reverse must be boolean.')
                if values and not (all(type(x) is str for x in values) or all(type(x) in (int,float) for x in values)):raise CodeError('invalid_value','sorted requires scalar strings or numbers.')
                return sorted(values,reverse=reverse)
            if name=='abs' and len(args)==1:return number(abs(number(args[0])))
            if name=='round' and 1<=len(args)<=2:
                digits=args[1] if len(args)==2 else kwargs.get('ndigits',0)
                if type(digits) is not int or not -308<=digits<=308:raise CodeError('invalid_value','Invalid round precision.')
                return number(round(number(args[0]),digits))
            if name=='range' and 1<=len(args)<=3 and all(type(x) is int for x in args):
                start,stop,step=(0,args[0],1) if len(args)==1 else (args[0],args[1],args[2] if len(args)==3 else 1)
                if not step:raise CodeError('invalid_value','range step cannot be zero.')
                count=max(0,(stop-start+(step-1 if step>0 else step+1))//step)
                if count>MAX_ITEMS:raise CodeError('value_limit','range exceeds its item limit.')
                self.tick(count);return list(range(start,stop,step))
            if name in ('str','int','float','bool') and len(args)==1 and (args[0] is None or type(args[0]) in (str,int,float,bool)):
                value={'str':str,'int':int,'float':float,'bool':bool}[name](args[0])
                if name in ('int','float'):number(value)
                return value
        except (ValueError,TypeError,ArithmeticError) as exc:
            if isinstance(exc,CodeError):raise
            raise CodeError('invalid_value','Invalid bounded function arguments.') from exc
        raise CodeError('invalid_value','Invalid approved function arguments.')
