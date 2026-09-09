package com.enterpriseiam.authorization;

import java.time.ZonedDateTime;

public record EnvironmentAttributes(ZonedDateTime time, String remoteAddress) { }
