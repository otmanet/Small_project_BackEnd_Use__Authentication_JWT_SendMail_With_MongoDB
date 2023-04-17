package com.example.restApi.Repository;

import java.util.Optional;

import org.springframework.data.mongodb.repository.MongoRepository;

import com.example.restApi.Models.ERole;
import com.example.restApi.Models.Role;

//repository has interfaces that extend Spring Data JPA MongoRepository to interact with Database.
public interface RoleRepository extends MongoRepository<Role, String> {

  Optional<Role> findByName(ERole name);
}
