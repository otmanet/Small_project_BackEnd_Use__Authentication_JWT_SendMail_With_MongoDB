package com.example.SpringAngular.Repository;

import com.example.SpringAngular.Model.ERole;
import com.example.SpringAngular.Model.Role;
import org.springframework.data.mongodb.repository.MongoRepository;

import java.util.Optional;
//repository has interfaces that extend Spring Data JPA MongoRepository to interact with Database.
public interface RoleRepository extends MongoRepository<Role,String> {

    Optional<Role> findByName(ERole name);
}
