package ru.vasire.keycloak.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.support.JpaRepositoryFactory;
import org.springframework.stereotype.Repository;
import ru.vasire.keycloak.model.Employee;

import java.util.Optional;


public interface EmployeeRepository extends JpaRepository<Employee, Integer> {

}
