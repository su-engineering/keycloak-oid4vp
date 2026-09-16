/* Copyright 2026 su-engineering. SPDX-License-Identifier: Apache-2.0 */
package io.github.suengineering.keycloak.oid4vp.mapper;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

import io.github.suengineering.keycloak.oid4vp.domain.PresentationType;
import io.github.suengineering.keycloak.oid4vp.domain.VerifiedCredential;
import io.github.suengineering.keycloak.oid4vp.util.Oid4vpMapperUtils;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.models.IdentityProviderMapperModel;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.UserModel;
import org.keycloak.sessions.AuthenticationSessionModel;

class MultiCredentialMappingTest {
    @Test
    void queryIdSelectsClaimsEvenWhenTypesAndClaimNamesAreIdentical() {
        var context = context();
        var selected = mapper(Map.of("credential.query.id", "other", "credential.type", "Membership"));
        assertThat(Oid4vpMapperUtils.matchesCredential(selected, context)).isTrue();
        assertThat(Oid4vpMapperUtils.getClaimValue(context, "sub", selected)).isEqualTo("Bob");
        assertThat(Oid4vpMapperUtils.getClaimValue(context, "sub", mapper(Map.of())))
                .isEqualTo("Alice");
        selected.getConfig().put("credential.format", "mso_mdoc");
        assertThat(Oid4vpMapperUtils.matchesCredential(selected, context)).isFalse();
        assertThat(Oid4vpMapperUtils.getClaimValue(context, "sub", selected)).isNull();
    }

    @Test
    void credentialTypeCanSelectANonIdentityCredential() {
        var selected = mapper(Map.of("credential.type", "License"));
        assertThat(Oid4vpMapperUtils.getClaimValue(context(), "category", selected))
                .isEqualTo("A");
        assertThat(Oid4vpMapperUtils.matchesCredential(mapper(Map.of("credential.query.id", "missing")), context()))
                .isFalse();
    }

    @Test
    void ambiguousScalarMappingRejectsInsteadOfUsingFirstMatch() {
        var selected = mapper(Map.of("credential.type", "Membership"));
        assertThatThrownBy(() -> Oid4vpMapperUtils.getClaimValue(context(), "sub", selected))
                .hasMessageContaining("Mapper matches multiple credentials");
    }

    @Test
    void userAttributeMapperCanMapFromAdditionalCredentials() {
        var selected =
                mapper(Map.of("credential.query.id", "other", "claim", "sub", "user.attribute", "other_subject"));
        UserModel user = mock(UserModel.class);
        new Oid4vpClaimToUserAttributeMapper().importNewUser(null, null, user, selected, context());
        verify(user).setAttribute("other_subject", List.of("Bob"));
    }

    @Test
    void multivaluedAttributeMapperKeepsValuesFromEveryPresentationIncludingRepeatedQuery() {
        var context = context();
        Oid4vpMapperUtils.storeCredentials(
                context,
                Map.of(
                        "members",
                        List.of(
                                credential("members", "Membership", Map.of("groups", List.of("gold", "active"))),
                                credential("members", "Membership", Map.of("groups", List.of("professional"))))));
        var selected = mapper(Map.of(
                "credential.query.id",
                "members",
                "claim",
                "groups",
                "user.attribute",
                "groups",
                "multivalued",
                "true"));
        UserModel user = mock(UserModel.class);
        new Oid4vpClaimToUserAttributeMapper().importNewUser(null, null, user, selected, context);
        verify(user).setAttribute("groups", List.of("gold", "active", "professional"));
    }

    @Test
    void multiCredentialSessionNotesUseJsonArrays() {
        var selected = mapper(Map.of(
                "credential.type",
                "Membership",
                "claim",
                "sub",
                Oid4vpClaimToUserSessionMapper.SESSION_NOTE,
                "subjects",
                "multivalued",
                "true"));
        var context = context();
        var authSession = mock(AuthenticationSessionModel.class);
        context.setAuthenticationSession(authSession);
        new Oid4vpClaimToUserSessionMapper().preprocessFederatedIdentity(null, null, selected, context);
        verify(authSession).setUserSessionNote("subjects", "[\"Alice\",\"Bob\"]");
    }

    private static BrokeredIdentityContext context() {
        var idp = new IdentityProviderModel();
        idp.setAlias("oid4vp");
        idp.setEnabled(true);
        var context = new BrokeredIdentityContext("user", idp);
        context.getContextData().put(Oid4vpMapperUtils.CONTEXT_CLAIMS_KEY, Map.of("sub", "Alice"));
        var all = new LinkedHashMap<String, List<VerifiedCredential>>();
        all.put("identity", List.of(credential("identity", "Membership", Map.of("sub", "Alice"))));
        all.put("other", List.of(credential("other", "Membership", Map.of("sub", "Bob"))));
        all.put("license", List.of(credential("license", "License", Map.of("category", "A"))));
        Oid4vpMapperUtils.storeCredentials(context, all);
        return context;
    }

    private static VerifiedCredential credential(String id, String type, Map<String, Object> claims) {
        return new VerifiedCredential(id, "issuer", type, claims, PresentationType.SD_JWT);
    }

    private static IdentityProviderMapperModel mapper(Map<String, String> values) {
        var mapper = new IdentityProviderMapperModel();
        mapper.setConfig(new LinkedHashMap<>(values));
        return mapper;
    }
}
