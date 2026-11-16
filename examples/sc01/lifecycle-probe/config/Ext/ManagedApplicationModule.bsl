// LaunchParameter is a client property. Pass the explicit /C value to the server module.
// This test configuration has no default output directory and never creates one.
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
