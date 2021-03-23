package org.thomas.mapper;

import org.apache.ibatis.annotations.Select;
import org.thomas.entity.PermissionEntity;

import java.util.List;


public interface PermissionMapper {

    @Select(" select * from sys_permission ")
    List<PermissionEntity> findAllPermission();

}
