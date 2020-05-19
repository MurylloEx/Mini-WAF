const SafetyFilterType = {
    FILTER_VALIDATE_NUMBER_INT:     0x01,
    FILTER_VALIDATE_NUMBER_FLOAT:   0x02,
    FILTER_VALIDATE_STRING:         0x04,
    FILTER_VALIDATE_EMAIL:          0x08,
    FILTER_VALIDATE_BOOLEAN:        0x10
}

const SafetyAntiXssType = {
    FILTER_ANTI_XSS_ENCODE_DEFAULT:          0x01,
    FILTER_ANTI_XSS_ENCODE_QUOTES:           0x02,
    FILTER_ANTI_XSS_ENCODE_NOQUOTES:         0x04,
    FILTER_ANTI_XSS_ENCODE_ONLYSPECIAL:      0x08
}

const SafetyFilter = {
    
    /**Valida entradas numéricas
     * 
     * @param {string} input Entrada a ser validada.
     * @param {number} filterType Tipo de validação a ser aplicada.
     */
    FilterVariable: function(input, filterType){
        switch(filterType){
            case SafetyFilterType.FILTER_VALIDATE_NUMBER_INT: //Standard of ECMA since 2019.
                return (Number(input) == input && input % 1 === 0);
            case SafetyFilterType.FILTER_VALIDATE_NUMBER_FLOAT: //Standard of ECMA since 2019.
                return (Number(input) == input);
            case SafetyFilterType.FILTER_VALIDATE_STRING: //Mantém apenas 
                return !new RegExp(/[^a-zA-Z0-9 ]/g).test(input);
            case SafetyFilterType.FILTER_VALIDATE_EMAIL: //https://emailregex.com/ RFC 5322
                return (new RegExp(/^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/)).test(input);
            case SafetyFilterType.FILTER_VALIDATE_BOOLEAN: 
                return (Boolean(input) == input && typeof(input) === typeof(true));
            default:
                return input;
        }
    },

    /**Codifica uma string em um formato de escape html válido.
     * 
     * @param {string} input Entrada a ser filtrada.
     * @param {number} antiXssType Tipo de filtro a ser aplicado.
     */
    FilterAntiXSS: function(input, antiXssType){
        let buffer = [];
        const EncodeDefault = ((antiXssType & SafetyAntiXssType.FILTER_ANTI_XSS_ENCODE_DEFAULT) == SafetyAntiXssType.FILTER_ANTI_XSS_ENCODE_DEFAULT);
        const EncodeQuotes = ((antiXssType & SafetyAntiXssType.FILTER_ANTI_XSS_ENCODE_QUOTES) == SafetyAntiXssType.FILTER_ANTI_XSS_ENCODE_QUOTES);
        const EncodeNoQuotes = ((antiXssType & SafetyAntiXssType.FILTER_ANTI_XSS_ENCODE_NOQUOTES) == SafetyAntiXssType.FILTER_ANTI_XSS_ENCODE_NOQUOTES);
        const EncodeOnlySpecial = ((antiXssType & SafetyAntiXssType.FILTER_ANTI_XSS_ENCODE_ONLYSPECIAL) == SafetyAntiXssType.FILTER_ANTI_XSS_ENCODE_ONLYSPECIAL);
        if (!EncodeDefault && !EncodeQuotes && !EncodeNoQuotes && !EncodeOnlySpecial){
            return false;
        }
        for (let k = input.length-1; k >= 0; k--){
            let chcode = input[k].charCodeAt();
            let alreadyEncoded = false;
            if (EncodeOnlySpecial){
                //Codifica os especiais: &#<>/\;
                if (chcode == 0x2f || chcode == 0x3c || chcode == 0x3e || chcode == 0x26 || chcode == 0x23 || chcode == chcode || chcode == 0x3b){
                    buffer.unshift(['&#', chcode, ';'].join(''));
                    alreadyEncoded = true;
                }
                //Codifica as aspas somente se EncodeNoQuotes não estiver definido.
                if (!EncodeNoQuotes && EncodeQuotes && !EncodeDefault){
                    if (chcode == 0x22 || chcode == 0x27){
                        buffer.unshift(['&#', chcode, ';'].join(''));
                        alreadyEncoded = true;
                    }
                }
                if (EncodeDefault && !EncodeNoQuotes){ //Codifica somente aspas duplas.
                    if (chcode == 0x22){
                        buffer.unshift(['&#', chcode, ';'].join(''));
                        alreadyEncoded = true;
                    }
                }
            }
            else{
                if (EncodeDefault && !EncodeNoQuotes){ //Codifica tudo menos aspas simples.
                    if (chcode != 0x27){
                        buffer.unshift(['&#', chcode, ';'].join(''));
                        alreadyEncoded = true;
                    }
                }
                else{
                    if (EncodeQuotes && !EncodeNoQuotes){ //Codifica tudo, incluindo aspas duplas e aspas simples.
                        buffer.unshift(['&#', chcode, ';'].join(''));
                        alreadyEncoded = true;
                    }
                    else{
                        if (chcode != 0x22 && chcode != 0x27){ //Tudo menos aspas duplas e aspas simples.
                            buffer.unshift(['&#', chcode, ';'].join(''));
                            alreadyEncoded = true;
                        }
                    }
                }
            }
            if (!alreadyEncoded){
                buffer.unshift(input[k]);
            }
        }
        return buffer.join('');
    },

    /**Decodifica a string em formato anti-xss html.
     * 
     * @param {string} input 
     */
    FilterDecodeAntiXSS: function(input) {
        return input.replace(/&#(\d+);/g, function(match, dec) {
            return String.fromCharCode(dec);
        });
    }

}

module.exports = {
    SafetyFilterType: SafetyFilterType,
    SafetyAntiXssType: SafetyAntiXssType,
    SafetyFilter: SafetyFilter
}