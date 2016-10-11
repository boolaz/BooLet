// -----------------------------------------------------------
// Name       : ANOMALY_COMMON.YAR
// Purpose    : Detecting anomalies common to multiple fields
// Revision   : 1.0 (2016-08-06)
// Author     : Bruno Valentin - bruno@boolaz.com
// Updates    : https://github.com/boolaz/BooLet
// Reference  : http://www.brunovalentin.com/dev/
// -----------------------------------------------------------

// directory traversal -----------------

rule dirtrav : Directory_TRaversal
{
    meta:
        description = "directory traversal"
        author = "Bruno Valentin (bruno@boolaz.com)"
        last_updated = "2016-08-06"

    strings:
        $ = /(\.|%2e|%252e)(\.|%2e|%252e)(\/|\\|%2f|%5c|%252f|%255c|%c0%af|%c1%9c)(\.|%2e|%252e)(\.|%2e|%252e)/

    condition:
        any of them
}

// shells access--------------------------
rule shell : SHell_Access
{
    meta:
        description = "shell access attempt"
        author = "Bruno Valentin (bruno@boolaz.com)"
        last_updated = "2016-08-06"

    strings:
        $ = /\(\)/ nocase
        $ = /(\/|\\|%2f|%252f|%c0%af)usr(\/|\\|%2f|%252f|%c0%af)bin/ nocase
        $ = /(\/|\\|%2f|%252f|%c0%af)bin/ nocase

    condition:
        any of them
}

// Encoded string-------------------------
rule encoded : Encoded_string
{
    meta:
        description = "encoded string"
        author = "Bruno Valentin (bruno@boolaz.com)"
        last_updated = "2016-08-06"

    strings:
        $ = /(%[0-9a-f]{2}){5,}/ nocase

    condition:
        any of them
}
    
// long field --------------------------
rule longfield : Unusual_long_field
{
    meta:
        description = "Unusual long field"
        author = "Bruno Valentin (bruno@boolaz.com)"
        last_updated = "2016-08-06"

    condition:
        strlen > 1000
}