package es.limit.auth;

import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.ProtocolMapperUtils;
import org.keycloak.protocol.oidc.mappers.*;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.IDToken;

import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.GenericType;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.util.*;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

public class LimitAuthConceptKeycloakMapper extends AbstractOIDCProtocolMapper implements OIDCAccessTokenMapper, OIDCIDTokenMapper, UserInfoTokenMapper {

    public static final String PROVIDER_ID = "limit-auth-concept-keycloak-mapper";

    private static final List<ProviderConfigProperty> configProperties = new ArrayList<>();

    static {
        ProviderConfigProperty property = new ProviderConfigProperty();
        property.setName("limit.auth.url");
        property.setLabel("URL del servei");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        property.setHelpText("URL del servei d'autenticació de Limit");
        configProperties.add(property);

        // The builtin protocol mapper let the user define under which claim name (key)
        // the protocol mapper writes its value. To display this option in the generic dialog
        // in keycloak, execute the following method.
        OIDCAttributeMapperHelper.addTokenClaimNameConfig(configProperties);

        // The builtin protocol mapper let the user define for which tokens the protocol mapper
        // is executed (access token, id token, user info). To add the config options for the different types
        // to the dialog execute the following method. Note that the following method uses the interfaces
        // this token mapper implements to decide which options to add to the config. So if this token
        // mapper should never be available for some sort of options, e.g. like the id token, just don't
        // implement the corresponding interface.
        OIDCAttributeMapperHelper.addIncludeInTokensConfig(configProperties, LimitAuthConceptKeycloakMapper.class);
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayType() {
        return "Limit Role Mapper";
    }

    @Override
    public String getDisplayCategory() {
        return "Token mapper";
    }

    @Override
    public String getHelpText() {
        return "Afegeix rols de Limit, depenent del client i dels paràmetres 'Identificador' i 'empresa' de la petició";
    }

    @Override
    public int getPriority() {
        return ProtocolMapperUtils.PRIORITY_ROLE_MAPPER;
    }


    @Override
    protected void setClaim(IDToken token, ProtocolMapperModel mappingModel, UserSessionModel userSession, KeycloakSession keycloakSession, ClientSessionContext clientSessionCtx) {

        String identificador = null;
        String empresa = null;

        List<String> identificadors = keycloakSession.getContext().getRequestHeaders().getRequestHeader("limit-identificador");
        if (identificadors != null && !identificadors.isEmpty())
            identificador = identificadors.get(0);

        List<String> empreses = keycloakSession.getContext().getRequestHeaders().getRequestHeader("limit-empresa");
        if (empreses != null && !empreses.isEmpty())
            empresa = empreses.get(0);

        System.out.println("Identificador: " + identificador);
        System.out.println("Empresa: " + empresa);

        Set<String> limitRols = new HashSet<>();

        // Obtenir client i fer crida a API REST Permisos Limit
        String path = "localhost:8082/usuaris/USER_CODE/rols";
        String limitUrl = mappingModel.getConfig().get("limit.auth.url");
        if (limitUrl != null && !limitUrl.isEmpty())
            path = limitUrl + (limitUrl.endsWith("/") ? "" : "/");
        path = path.replace("USER_CODE", userSession.getUser().getUsername());

        String username="limit";
        String password="tecnologies";
        String usernameAndPassword = username + ":" + password;
        String authorizationHeaderValue = "Basic " + java.util.Base64.getEncoder().encodeToString( usernameAndPassword.getBytes() );

        Client client = ClientBuilder.newBuilder().build();
        WebTarget target = client.target(path);
        Response response = target.request(MediaType.APPLICATION_JSON)
                .header("Authorization", authorizationHeaderValue)
                .header("limit-identificador", identificador)
                .header("limit-empresa", empresa)
                .get();
        // String str_rols = response.readEntity(String.class);
        List<String> rols = response.readEntity(new GenericType<List<String>>(){});
        response.close();  // You should close connections!

//        List<String> rols = new ArrayList<String>(Arrays.asList(
//                str_rols.replace("[", "")
//                        .replace("]", "")
//                        .split(",")));

        if (rols != null && !rols.isEmpty())
            limitRols = new HashSet<String>(rols);

        setClaim(token, mappingModel, limitRols, null, null);
    }

    /**
     * Retrieves all roles of the current user based on direct roles set to the user, its groups and their parent groups.
     * Then it recursively expands all composite roles, and restricts according to the given predicate {@code restriction}.
     * If the current client sessions is restricted (i.e. no client found in active user session has full scope allowed),
     * the final list of roles is also restricted by the client scope. Finally, the list is mapped to the token into
     * a claim.
     *
     * @param token
     * @param mappingModel
     * @param rolesToAdd
     * @param clientId
     * @param prefix
     */
    private static void setClaim(
            IDToken token,
            ProtocolMapperModel mappingModel,
            Set<String> rolesToAdd,
            String clientId,
            String prefix) {

        Set<String> realmRoleNames;
        if (prefix != null && !prefix.isEmpty()) {
            realmRoleNames = rolesToAdd.stream()
                    .map(roleName -> prefix + roleName)
                    .collect(Collectors.toSet());
        } else {
            realmRoleNames = rolesToAdd;
        }

        Object claimValue = realmRoleNames;

//        boolean multiValued = "true".equals(mappingModel.getConfig().get(ProtocolMapperUtils.MULTIVALUED));
//        if (!multiValued) {
//            claimValue = realmRoleNames.toString();
//        }

        mapClaim(token, mappingModel, claimValue, clientId);
    }

    private static final Pattern CLIENT_ID_PATTERN = Pattern.compile("\\$\\{client_id\\}");

    private static final Pattern DOT_PATTERN = Pattern.compile("\\.");
    private static final String DOT_REPLACEMENT = "\\\\\\\\.";

    private static void mapClaim(
            IDToken token,
            ProtocolMapperModel mappingModel,
            Object attributeValue,
            String clientId) {
//        attributeValue = OIDCAttributeMapperHelper.mapAttributeValue(mappingModel, attributeValue);
        if (attributeValue == null) return;

        String protocolClaim = mappingModel.getConfig().get(OIDCAttributeMapperHelper.TOKEN_CLAIM_NAME);
        System.out.println("Claim: " + protocolClaim);
        if (protocolClaim == null) {
            return;
        }

        if (clientId != null) {
            // case when clientId contains dots
            clientId = DOT_PATTERN.matcher(clientId).replaceAll(DOT_REPLACEMENT);
            protocolClaim = CLIENT_ID_PATTERN.matcher(protocolClaim).replaceAll(clientId);
        }

        List<String> split = OIDCAttributeMapperHelper.splitClaimPath(protocolClaim);

        // Special case
        if (checkAccessToken(token, split, attributeValue)) {
            return;
        }

        final int length = split.size();
        int i = 0;
        Map<String, Object> jsonObject = token.getOtherClaims();
        for (String component : split) {
            i++;
            if (i == length) {
                // Case when we want to add to existing set of roles
                Object last = jsonObject.get(component);
                if (last instanceof Collection && attributeValue instanceof Collection) {
                    ((Collection) last).addAll((Collection) attributeValue);
                } else {
                    jsonObject.put(component, attributeValue);
                }

            } else {
                Map<String, Object> nested = (Map<String, Object>)jsonObject.get(component);

                if (nested == null) {
                    nested = new HashMap<>();
                    jsonObject.put(component, nested);
                }

                jsonObject = nested;
            }
        }
    }

    // Special case when roles are put to the access token via "realmAcces, resourceAccess" properties
    private static boolean checkAccessToken(IDToken idToken, List<String> path, Object attributeValue) {
        if (!(idToken instanceof AccessToken)) {
            return false;
        }

        if (!(attributeValue instanceof Collection)) {
            return false;
        }

        Collection<String> roles = (Collection<String>) attributeValue;

        AccessToken token = (AccessToken) idToken;
        AccessToken.Access access = null;
        if (path.size() == 2 && "realm_access".equals(path.get(0)) && "roles".equals(path.get(1))) {
            access = token.getRealmAccess();
            if (access == null) {
                access = new AccessToken.Access();
                token.setRealmAccess(access);
            }
        } else if (path.size() == 3 && "resource_access".equals(path.get(0)) && "roles".equals(path.get(2))) {
            String clientId = path.get(1);
            access = token.addAccess(clientId);
        } else {
            return false;
        }

        for (String role : roles) {
            access.addRole(role);
        }
        return true;
    }
}
