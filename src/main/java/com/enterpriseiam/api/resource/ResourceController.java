package com.enterpriseiam.api.resource;

import com.enterpriseiam.resource.ResourceReference;
import com.enterpriseiam.resource.ResourceService;
import jakarta.validation.Valid;
import java.util.UUID;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** RBAC permissions and ABAC are evaluated together within the audited, transactional service. */
@RestController
@RequestMapping(value = "/api/v1/resources", produces = MediaType.APPLICATION_JSON_VALUE)
public class ResourceController {
    private final ResourceService resources;
    private final ResourceResponseMapper mapper;

    public ResourceController(ResourceService resources, ResourceResponseMapper mapper) {
        this.resources = resources;
        this.mapper = mapper;
    }

    @GetMapping("/{id}")
    public ResourceResponse read(@PathVariable UUID id) {
        return mapper.toResponse(resources.read(new ResourceReference(id)));
    }

    @PutMapping(value = "/{id}", consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResourceResponse write(@PathVariable UUID id, @Valid @RequestBody ResourceUpdateRequest request) {
        return mapper.toResponse(resources.write(new ResourceReference(id), request.content(), request.expectedVersion()));
    }
}
