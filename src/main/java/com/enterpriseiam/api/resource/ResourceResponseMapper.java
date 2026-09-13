package com.enterpriseiam.api.resource;

import com.enterpriseiam.resource.ResourceSnapshot;
import org.mapstruct.Mapper;
import org.mapstruct.ReportingPolicy;

@Mapper(componentModel = "spring", unmappedTargetPolicy = ReportingPolicy.ERROR)
public interface ResourceResponseMapper {
    ResourceResponse toResponse(ResourceSnapshot resource);
}
