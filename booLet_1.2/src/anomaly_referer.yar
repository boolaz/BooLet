// -----------------------------------------------------------
// Name       : REFERER.YAR
// Purpose    : detecting anomalies in referer field with booLET
// Revision   : 1.0 (2016-08-06)
// Author     : Bruno Valentin - bruno@boolaz.com
// Updates    : https://github.com/boolaz/BooLet
// Reference  : http://www.brunovalentin.com/dev/
// -----------------------------------------------------------

include "anomaly_common.yar"

// long Referer --------------------------
rule ulr : unusual long referer
{
    meta:
        description = "unusual long referer"
        author = "Bruno Valentin (bruno@boolaz.com)"
        last_updated = "2016-08-06"

    condition:
        filesize > 1000
}