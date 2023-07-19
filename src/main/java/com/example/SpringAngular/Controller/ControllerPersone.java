package com.example.SpringAngular.Controller;

import com.example.SpringAngular.Model.Persone;
import net.minidev.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.data.mongodb.core.query.Criteria;
import org.springframework.data.mongodb.core.query.Query;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@CrossOrigin(origins = "http://localhost:4200")
@RestController
@RequestMapping("api/v0")
public class ControllerPersone {
    @Autowired
    private MongoTemplate mongoTemplate;

    @GetMapping("/Persone")
    public List<Persone> getPersone(){
        List<Persone> listPersone=mongoTemplate.findAll(Persone.class);
        return listPersone;
    }

    @GetMapping("Persone/{id}")
    public ResponseEntity<Persone> getPersoneById(@PathVariable(name="id") Long id){
        Query query=new Query();
        query.addCriteria(Criteria.where("id").is(id));
        Persone persone=mongoTemplate.findOne(query,Persone.class);
        return  ResponseEntity.ok(persone);
    }
    @PostMapping("/Persone")
    public Persone addPersone(@RequestBody Persone persone)
    {
        return mongoTemplate.save(persone);
    }

    @DeleteMapping("Persone/{id}")
    public ResponseEntity<Map<String,Boolean>> DeletePersone(@PathVariable(name="id") Long id){
        Query query=new Query();
        query.addCriteria(Criteria.where("id").is(id));
        Persone persone=mongoTemplate.findOne(query,Persone.class);
        mongoTemplate.remove(persone);
        Map<String,Boolean> Response=new HashMap<>();
        Response.put("Deleted",Boolean.TRUE);
        return ResponseEntity.ok(Response);
    }

    @PutMapping("Persone/{id}")
    public ResponseEntity<Persone> UpdatePersone(@PathVariable(name="id")  Long id, @RequestBody Persone NewPersone){
        Query query=new Query();
        query.addCriteria(Criteria.where("id").is(id)); 
        Persone persone=mongoTemplate.findOne(query,Persone.class);
        persone.setFirstname(NewPersone.getFirstname());
        persone.setLastname(NewPersone.getLastname());
        persone.setBirthday(NewPersone.getBirthday());
        persone.setCity(NewPersone.getCity());
        Persone persone1=mongoTemplate.save(persone);
        return ResponseEntity.ok(persone1);
    }

}
