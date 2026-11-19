# libSceIcu

## add Functional

- [ucnv_countAliases and ucnv_getAlias](../../../core/libs/prx/libSceIcu/ConverterAliases.cpp) follow bundled ICU 78.1 [ucnv_io.cpp](https://github.com/unicode-org/icu/blob/049e0d6a420629ac7db77256987d083a563287b5/icu4c/source/common/ucnv_io.cpp#L863-L911) with guest-safe strings and status access; the PS5 ABI and behavior remain unmeasured. An invalid or unreadable status or alias pointer throws `NotImplemented_nid_no_patch` preserving host `errno`. ICU owns the returned strings for the process lifetime, visible in AnyPS5's unified address space. The reduced bundled ICU data package omits `cnvalias.icu`, so queries report missing alias data until compatible common data is supplied. Closes when: compared with the console and converter alias data is bundled.
