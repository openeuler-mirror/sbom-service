package org.opensourceway.sbom.dao;

import org.opensourceway.sbom.model.entity.ProductVulRef;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.UUID;

public interface ProductVulRefRepository extends JpaRepository<ProductVulRef, UUID> {
    @Query(value = "SELECT evr.id, v.vul_id, pvi.issue_id, pvi.vul_status, pvi.issue_status, p.name, p.download_location FROM external_vul_ref evr " +
            "JOIN package p ON evr.pkg_id = p.id " +
            "JOIN vulnerability v ON evr.vul_id = v.id " +
            "JOIN package_vul_issue pvi ON v.vul_id = pvi.cve_number " +
            "WHERE p.sbom_id = (SELECT id FROM sbom WHERE product_id = (SELECT id FROM product WHERE name = :productName)) " +
            "AND (:vulId IS NULL OR v.vul_id = :vulId ) " +
            "AND (:issueId IS NULL OR pvi.issue_id = :issueId) " +
            "AND (:vulStatus IS NULL OR pvi.vul_status = :vulStatus) " +
            "AND (:issueStatus IS NULL OR pvi.issue_id = :issueStatus) " +
            "AND (:rpmName IS NULL OR p.name LIKE CONCAT('%', :rpmName, '%')) ",
            nativeQuery = true)
    Page<ProductVulRef> findByProductName(@Param("productName") String productName,
                                          @Param("vulId") String vulId,
                                          @Param("issueId") String issueId,
                                          @Param("vulStatus") String vulStatus,
                                          @Param("issueStatus") String issueStatus,
                                          @Param("rpmName") String rpmName,
                                          Pageable pageable);
}
