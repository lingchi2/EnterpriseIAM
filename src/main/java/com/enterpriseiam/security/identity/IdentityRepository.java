package com.enterpriseiam.security.identity;

import com.enterpriseiam.identity.domain.User;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.Repository;
import org.springframework.data.repository.query.Param;

public interface IdentityRepository extends Repository<User, UUID> {

    Optional<User> findByEmail(String email);

    @Query("""
            select new com.enterpriseiam.security.identity.AccountAttributes(
                u.id, u.email, u.status, u.department, u.clearanceLevel)
            from User u where u.id = :id
            """)
    Optional<AccountAttributes> findAttributes(@Param("id") UUID id);

    @Query("select distinct r.name from User u join u.roles r where u.id = :id")
    Set<String> findRoleNames(@Param("id") UUID id);

    @Query("""
            select distinct p.name from User u join u.roles r join r.permissions p
            where u.id = :id
            """)
    Set<String> findPermissionNames(@Param("id") UUID id);
}
