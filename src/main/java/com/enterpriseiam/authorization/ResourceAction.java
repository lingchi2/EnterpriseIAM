package com.enterpriseiam.authorization;

public enum ResourceAction {
    READ, WRITE;

    public String requiredPermission() {
        return "RESOURCE:" + name();
    }
}
