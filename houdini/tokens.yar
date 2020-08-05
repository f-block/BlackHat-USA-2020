rule houdini_tokens {
    strings:
        $dll_token       = "BLACKHAT_USA_2020_what.the.eyes.see.and.the.ears.hear..the.mind.believes_BLACKHAT_USA_2020" ascii wide
        $shellcode_token = "AAAAAAAAAAAAAAAAAA_what.the.eyes.see.and.the.ears.hear..the.mind.believes_AAAAAAAAAAAAAAAAAA" ascii wide

    condition:
        any of them
}
