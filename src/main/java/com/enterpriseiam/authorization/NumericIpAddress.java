package com.enterpriseiam.authorization;

/** Validates IP literals before Spring's matcher sees them; hostnames never reach a resolver. */
final class NumericIpAddress {
    private NumericIpAddress() { }

    static boolean isLiteral(String value) {
        if (value == null || value.isEmpty() || value.length() > 45) {
            return false;
        }
        return value.indexOf(':') >= 0 ? isIpv6(value) : isIpv4(value);
    }

    private static boolean isIpv4(String value) {
        String[] octets = value.split("\\.", -1);
        if (octets.length != 4) {
            return false;
        }
        for (String octet : octets) {
            if (octet.isEmpty() || octet.length() > 3
                    || (octet.length() > 1 && octet.charAt(0) == '0')) {
                return false;
            }
            int number = 0;
            for (char digit : octet.toCharArray()) {
                if (digit < '0' || digit > '9') {
                    return false;
                }
                number = number * 10 + digit - '0';
            }
            if (number > 255) {
                return false;
            }
        }
        return true;
    }

    private static boolean isIpv6(String value) {
        int compression = value.indexOf("::");
        if (compression >= 0 && value.indexOf("::", compression + 2) >= 0) {
            return false;
        }
        if ((value.startsWith(":") && !value.startsWith("::"))
                || (value.endsWith(":") && !value.endsWith("::"))) {
            return false;
        }
        String[] groups = value.split(":", -1);
        int words = 0;
        for (int index = 0; index < groups.length; index++) {
            String group = groups[index];
            if (group.isEmpty()) {
                continue;
            }
            if (group.indexOf('.') >= 0) {
                if (index != groups.length - 1 || !isIpv4(group)) {
                    return false;
                }
                words += 2;
                continue;
            }
            if (group.length() > 4) {
                return false;
            }
            for (char digit : group.toCharArray()) {
                if (!(digit >= '0' && digit <= '9') && !(digit >= 'a' && digit <= 'f')
                        && !(digit >= 'A' && digit <= 'F')) {
                    return false;
                }
            }
            words++;
        }
        // A triple colon is never valid; compression must represent at least one word.
        return !value.contains(":::") && (compression >= 0 ? words < 8 : words == 8);
    }
}
