package ru.vasire.keycloak.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import ru.vasire.keycloak.model.Employee;


public interface EmployeeRepository extends JpaRepository<Employee, Integer> {

}
