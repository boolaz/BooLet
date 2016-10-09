// -----------------------------------------------------------
// Name       : URI.YAR
// Purpose    : detecting anomalies in URI field with booLET
// Revision   : 1.0 (2016-08-06)
// Author     : Bruno Valentin - bruno@boolaz.com
// Updates    : https://github.com/boolaz/BooLet
// Reference  : http://www.brunovalentin.com/dev/
// -----------------------------------------------------------

include "anomaly_common.yar"

// SQLI ---------------------------------
rule sqli : SQL injection
{
    meta:
        description = "SQL Injection attempt"
        author = "Bruno Valentin (bruno@boolaz.com)"
        last_updated = "2016-08-06"

    strings:
        $s_insert = "INSERT" nocase
        $s_into = "INTO" nocase
        $s_select = "SELECT" nocase
        $s_from = "FROM" nocase 
        $s_drop = "DROP" nocase
        $s_table = "TABLE" nocase
        $s_database = "DATABASE" nocase
        $s_schema = "SCHEMA" nocase
        $s_union = "UNION" nocase
        $s_concat = "CONCAT" nocase

    condition:
        ($s_insert and $s_into) or 
        ($s_select and $s_from) or 
        ($s_drop and $s_table) or 
        ($s_drop and $s_database) or 
        ($s_select and $s_schema) or
        ($s_union and $s_select) or
        ($s_select and $s_concat)
}

// php shells --------------------------
rule phpshell : PHP Shell
{
    meta:
        description = "PHP Shell"
        author = "Bruno Valentin (bruno@boolaz.com)"
        last_updated = "2016-08-06"

    strings:
        $ = "c99.php" nocase
        $ = "r57.php" nocase

    condition:
        any of them
}

// XSS ---------------------------------
rule xss : Cross site scripting
{
    meta:
        description = "cross site scripting"
        author = "Bruno Valentin (bruno@boolaz.com)"
        last_updated = "2016-08-06"

    strings:
        $ = /(<|%3c)script.*(>|%3e).+(<|%3c)\/.*script(>|%3e)/ nocase
        $ = /alert\(.+\)/ nocase
        $ = "document.cookie" nocase
        
    condition:
        any of them
}

// SQL file ----------------------------
rule sqlfile : sqlfile
{
    meta:
        description = "SQL file"
        author = "Bruno Valentin (bruno@boolaz.com)"
        last_updated = "2016-08-06"

    strings:
        $ = /\.sql$/ nocase

    condition:
        any of them
}