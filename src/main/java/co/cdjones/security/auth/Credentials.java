package co.cdjones.security.auth;

import lombok.Builder;
import lombok.Data;
import lombok.experimental.Accessors;

/**
 * @author chrisjones
 * @date 11/10/2017
 */
@Data
@Builder
@Accessors(fluent = true)
public class Credentials {
    private String user;
    private String password;
    private String host;
}
