// -----------------------------------------------------------
// Name       : ANOMALY_AGENT.YAR
// Purpose    : detecting anomalies in agent field with booLET
// Revision   : 1.0 (2016-08-06)
// Author     : Bruno Valentin - bruno@boolaz.com
// Updates    : https://github.com/boolaz/BooLet
// Reference  : http://www.brunovalentin.com/dev/
// -----------------------------------------------------------

include "anomaly_common.yar"

// SQLi agent --------------------------
rule sqliagent : SQLi_agent
{
    meta:
        description = "SQLi Agent"
        author = "Bruno Valentin (bruno@boolaz.com)"
        last_updated = "2016-08-06"

    strings:
        $ = /(sqlmap|havij)/ nocase

    condition:
        any of them
}
