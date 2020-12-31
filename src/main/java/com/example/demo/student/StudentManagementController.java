package com.example.demo.student;

import org.springframework.web.bind.annotation.*;

import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("management/api/v1/students")
public class StudentManagementController {
    private static final List<Student> STUDENTS = Arrays.asList(
            new Student(1, "James Bond"),
            new Student(2, "Maria Jones"),
            new Student(3, "Anna Smith")
    );
    @GetMapping
    public List<Student> getAllStudents(){
        System.out.println("getAllStudents");
        return STUDENTS;
    }
    @PostMapping
    public void registerNewStudent(@RequestBody Student student){
        System.out.println("register");
        System.out.println(student);
    }
    @DeleteMapping(path = "{studentId}")
    public void deleteStudentById(@PathVariable("studentId") Integer id){
        System.out.println("delete");
        System.out.println(id);
    }
    @PutMapping(path = "{studentId}")
    public void updateStudent(@PathVariable("studentId") Integer id, @RequestBody Student student){
        System.out.println("update");
        System.out.println(String.format("%s %s ",id,student));
    }
}
