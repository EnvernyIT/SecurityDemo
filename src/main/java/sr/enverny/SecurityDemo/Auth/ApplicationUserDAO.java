package sr.enverny.SecurityDemo.Auth;

import java.util.Optional;

public interface ApplicationUserDAO {
    Optional<ApplicationUser> selectApplicationUserByUsername (String username);
}
