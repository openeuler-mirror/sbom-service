package org.opensourceway.sbom.dao;

import org.opensourceway.sbom.model.entity.Checksum;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;
import java.util.UUID;

public interface ChecksumRepository extends JpaRepository<Checksum, UUID> {

    @Query(value = "SELECT A.* FROM checksum A, package B WHERE A.pkg_id = B.id AND B.sbom_id = :sbomId",
            nativeQuery = true)
    List<Checksum> findBySbomId(UUID sbomId);
}