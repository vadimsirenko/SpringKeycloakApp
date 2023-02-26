package ru.vasire.keycloak.service;

import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import ru.vasire.keycloak.model.Employee;
import ru.vasire.keycloak.repository.EmployeeRepository;

import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Service
public class EmployeeService {

    @Autowired
    private EmployeeRepository employeeRepository;

    @PostConstruct
    public void initializeEmployeeTable() {
        long employeeCount = employeeRepository.count();
        if(employeeCount == 0) {
            employeeRepository.saveAll(
                    Stream.of(
                            new Employee("john", 20000),
                            new Employee("mak", 55000),
                            new Employee("peter", 120000)
                    ).collect(Collectors.toList()));
        }
    }

    public Employee getEmployee(int employeeId) {
        return employeeRepository
                .findById(employeeId)
                .orElse(null);
    }

    public List<Employee> getAllEmployees() {
        return employeeRepository
                .findAll();
    }
}