package org.opensourceway.sbom.dao;

import org.opensourceway.sbom.model.entity.SbomUser;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;
import java.util.UUID;

public interface SbomUserRepository extends JpaRepository<SbomUser, UUID> {

    @Query(value = "SELECT * FROM sbom_user WHERE login_name = :loginName ",
            nativeQuery = true)
    List<SbomUser> findSbomUser(String loginName);
}