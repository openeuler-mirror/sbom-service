package org.opensourceway.sbom.model.pojo.request.sbom;

import org.hibernate.annotations.CreationTimestamp;

import javax.persistence.Column;
import java.io.Serializable;
import java.sql.Timestamp;
import java.util.UUID;

public class SbomUserVo implements Serializable {
    private int id;

    /**
     * Name of a sbom user.
     */
    private String userName;

    /**
     * Name of a sbom login user
     */
    private String loginName;

    /**
     * Name of a sbom  user roleId
     */
    private String roleId;

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public String getUserName() {
        return userName;
    }

    public void setUserName(String userName) {
        this.userName = userName;
    }

    public String getLoginName() {
        return loginName;
    }

    public void setLoginName(String loginName) {
        this.loginName = loginName;
    }

    public String getRoleId() {
        return roleId;
    }

    public void setRoleId(String roleId) {
        this.roleId = roleId;
    }
}
