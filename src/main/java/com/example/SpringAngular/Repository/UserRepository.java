package com.example.SpringAngular.Repository;

import com.example.SpringAngular.Model.User;
import org.springframework.data.mongodb.repository.MongoRepository;

import java.util.Optional;
//repository has interfaces that extend Spring Data JPA MongoRepository to interact with Database.
public interface UserRepository extends MongoRepository<User,String> {

    Optional<User> findByUsername(String username);

    Boolean existsByUsername(String username);

    Boolean existsByEmail(String email);
}
