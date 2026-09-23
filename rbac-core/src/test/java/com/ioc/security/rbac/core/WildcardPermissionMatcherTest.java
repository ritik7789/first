package com.ioc.security.rbac.core;

import com.ioc.security.rbac.core.engine.WildcardPermissionMatcher;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import static org.assertj.core.api.Assertions.assertThat;

class WildcardPermissionMatcherTest {

    private final WildcardPermissionMatcher matcher = new WildcardPermissionMatcher();

    @ParameterizedTest(name = "{0} implies {1} = {2}")
    @CsvSource({
            "booking:read,          booking:read,         true",
            "booking:read,          BOOKING:READ,         true",
            "booking:read,          booking:cancel,       false",
            "booking:*,             booking:cancel,       true",
            "booking:*,             booking:seat:assign,  true",
            "booking:*,             flight:read,          false",
            "*:read,                flight:read,          true",
            "*:read,                flight:cancel,        false",
            "*:read,                flight:seat:read,     false",
            "*,                     anything:at:all,      true",
            "booking,               booking:read,         false",
            "booking:read,          booking,              false",
            "booking:read:own,      booking:read,         false",
            "booking:*,             booking:*,            true",
            "booking:read,          booking:*,            false",
    })
    void matches(String granted, String required, boolean expected) {
        assertThat(matcher.implies(granted, required)).isEqualTo(expected);
    }
}
