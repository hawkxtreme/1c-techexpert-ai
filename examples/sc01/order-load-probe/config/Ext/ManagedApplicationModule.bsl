// Isolated order-loading experiment. /C names an explicit JSON parameter file.
// No production base, output directory, network endpoint or credentials are implicit.
Процедура ПриНачалеРаботыСистемы()
    Попытка
        SC01Lifecycle.RunController(ПараметрЗапуска);
    Исключение
        // Missing/invalid /C must not write into an implicit working directory.
        // Exit code alone is not success: validate the final batch JSON.
        Сообщить("SC01 probe did not finish: " + ОписаниеОшибки());
    КонецПопытки;
    ЗавершитьРаботуСистемы(Ложь);
КонецПроцедуры
