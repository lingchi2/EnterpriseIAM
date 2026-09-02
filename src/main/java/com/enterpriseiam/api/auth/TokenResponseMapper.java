package com.enterpriseiam.api.auth;

import com.enterpriseiam.security.auth.TokenPair;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import org.mapstruct.ReportingPolicy;

@Mapper(componentModel = "spring", unmappedTargetPolicy = ReportingPolicy.ERROR)
public interface TokenResponseMapper {
    @Mapping(target = "tokenType", constant = "Bearer")
    TokenResponse toResponse(TokenPair tokens);
}
