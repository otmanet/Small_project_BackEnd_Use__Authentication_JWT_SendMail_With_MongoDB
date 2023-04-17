package com.example.restApi.Repository;

import java.util.Optional;

import org.springframework.data.mongodb.repository.MongoRepository;

import com.example.restApi.Models.User;

//repository has interfaces that extend Spring Data JPA MongoRepository to interact with Database.
public interface UserRepository extends MongoRepository<User, String> {

  Optional<User> findByUsername(String username);

  Boolean existsByUsername(String username);

  Boolean existsByEmail(String email);

}
