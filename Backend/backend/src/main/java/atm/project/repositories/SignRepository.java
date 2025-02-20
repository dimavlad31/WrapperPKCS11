package atm.project.repositories;

import atm.project.models.Signs;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface SignRepository extends JpaRepository<Signs, Long> {
}