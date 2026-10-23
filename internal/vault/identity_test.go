package vault_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ml0renz0/secretwright/internal/vault"
)

func accessEntityData() map[string]any {
	return map[string]any{
		"id": f06EntityID, "name": "app", "policies": []string{"app-read"}, "disabled": false,
		"metadata": map[string]any{"private": "private-f06-entity-metadata"},
		"aliases":  []any{map[string]any{"name": f06RoleID}},
	}
}

func accessGroupData(groupType string) map[string]any {
	return map[string]any{
		"id": f06GroupID, "name": "app-team", "type": groupType, "policies": []string{"app-read"},
		"member_entity_ids": []string{f06EntityID}, "member_group_ids": []string{f06MemberID},
		"metadata": map[string]any{"private": "private-f06-group-metadata"},
		"alias":    map[string]any{"name": "private-f06-group-alias"},
	}
}

func TestEntityCRUDUsesIDsAndProjectsOnlySupportedIdentityFields(t *testing.T) {
	var creates, updates, deletes atomic.Int32
	client := kvTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		accessRequest(t, r, "selected-token")
		switch {
		case r.URL.Path == "/v1/identity/entity/id" && kvOperation(r) == "LIST":
			kvReply(w, map[string]any{"keys": []string{f06MemberID, f06EntityID}, "key_info": map[string]any{f06EntityID: accessEntityData()}})
		case r.URL.Path == "/v1/identity/entity/id/"+f06EntityID && r.Method == http.MethodGet:
			kvReply(w, accessEntityData())
		case r.URL.Path == "/v1/identity/entity" && r.Method == http.MethodPost:
			creates.Add(1)
			body := kvWriteBody(t, r)
			want := map[string]any{"name": "app", "policies": []any{"app-read"}, "disabled": false}
			if !reflect.DeepEqual(body, want) {
				t.Error("entity creation forwarded unsupported fields or implicit policy metadata")
			}
			kvReply(w, map[string]any{"id": f06EntityID, "name": "app", "aliases": []string{"private-f06-create-alias"}})
		case r.URL.Path == "/v1/identity/entity/id/"+f06EntityID && r.Method == http.MethodPost:
			updates.Add(1)
			body := kvWriteBody(t, r)
			if body["disabled"] != true || len(body) != 3 {
				t.Error("entity update lost its explicit disabled state")
			}
			w.WriteHeader(http.StatusNoContent)
		case r.URL.Path == "/v1/identity/entity/id/"+f06EntityID && r.Method == http.MethodDelete:
			deletes.Add(1)
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Error("identity entity command used an unexpected endpoint")
			w.WriteHeader(http.StatusNotFound)
		}
	})
	ctx := context.Background()
	ids, err := client.ListEntities(ctx, "selected-token")
	if err != nil || !reflect.DeepEqual(ids, []string{f06EntityID, f06MemberID}) {
		t.Fatal("entity catalog did not return sorted IDs")
	}
	entity, err := client.ReadEntity(ctx, "selected-token", f06EntityID)
	if err != nil || entity.ID != f06EntityID || entity.Name != "app" || entity.Disabled || !reflect.DeepEqual(entity.Policies, []string{"app-read"}) {
		t.Fatal("entity read did not project its approved configuration")
	}
	accessAssertSafe(t, entity)
	result, err := client.WriteEntity(ctx, "selected-token", "", vault.EntitySpec{Name: "app", Policies: []string{"app-read"}})
	if err != nil || result.ID != f06EntityID {
		t.Fatal("entity creation did not return its identity ID")
	}
	accessAssertSafe(t, result)
	result, err = client.WriteEntity(ctx, "selected-token", f06EntityID, vault.EntitySpec{Name: "app", Policies: []string{"app-read"}, Disabled: true})
	if err != nil || result.ID != f06EntityID {
		t.Fatal("entity update did not retain the explicitly selected ID")
	}
	result, err = client.DeleteEntity(ctx, "selected-token", f06EntityID)
	if err != nil || !result.Deleted || creates.Load() != 1 || updates.Load() != 1 || deletes.Load() != 1 {
		t.Fatal("identity entity CRUD made unexpected mutations")
	}
	accessAssertSafe(t, result)
}

func TestInternalGroupCRUDReplacesExplicitMembershipWithoutReturningAliases(t *testing.T) {
	var writes, deletes atomic.Int32
	client := kvTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		accessRequest(t, r, "selected-token")
		switch {
		case r.URL.Path == "/v1/identity/group/id" && kvOperation(r) == "LIST":
			kvReply(w, map[string]any{"keys": []string{f06GroupID}, "key_info": map[string]any{f06GroupID: accessGroupData("internal")}})
		case r.URL.Path == "/v1/identity/group/name/app-team" && r.Method == http.MethodGet:
			w.WriteHeader(http.StatusNotFound)
		case r.URL.Path == "/v1/identity/group/id/"+f06GroupID && r.Method == http.MethodGet:
			kvReply(w, accessGroupData("internal"))
		case (r.URL.Path == "/v1/identity/group" || r.URL.Path == "/v1/identity/group/id/"+f06GroupID) && r.Method == http.MethodPost:
			writes.Add(1)
			want := map[string]any{
				"name": "app-team", "type": "internal", "policies": []any{"app-read"},
				"member_entity_ids": []any{f06EntityID}, "member_group_ids": []any{f06MemberID},
			}
			if !reflect.DeepEqual(kvWriteBody(t, r), want) {
				t.Error("group write did not set only its explicit internal membership and policies")
			}
			kvReply(w, map[string]any{"id": f06GroupID, "name": "app-team", "metadata": "private-f06-write-metadata"})
		case r.URL.Path == "/v1/identity/group/id/"+f06GroupID && r.Method == http.MethodDelete:
			deletes.Add(1)
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Error("identity group command used an unexpected endpoint")
			w.WriteHeader(http.StatusNotFound)
		}
	})
	ctx := context.Background()
	ids, err := client.ListGroups(ctx, "selected-token")
	if err != nil || !reflect.DeepEqual(ids, []string{f06GroupID}) {
		t.Fatal("group catalog did not return only its identity IDs")
	}
	group, err := client.ReadGroup(ctx, "selected-token", f06GroupID)
	if err != nil || group.ID != f06GroupID || group.Type != "internal" || !reflect.DeepEqual(group.MemberEntityIDs, []string{f06EntityID}) {
		t.Fatal("group read did not project its supported membership")
	}
	accessAssertSafe(t, group)
	spec := vault.GroupSpec{Name: "app-team", Policies: []string{"app-read"}, MemberEntityIDs: []string{f06EntityID, f06EntityID}, MemberGroupIDs: []string{f06MemberID}}
	for _, id := range []string{"", f06GroupID} {
		result, err := client.WriteGroup(ctx, "selected-token", id, spec)
		if err != nil || result.ID != f06GroupID {
			t.Fatal("internal group write did not return its selected identity ID")
		}
		accessAssertSafe(t, result)
	}
	result, err := client.DeleteGroup(ctx, "selected-token", f06GroupID)
	if err != nil || !result.Deleted || writes.Load() != 2 || deletes.Load() != 1 {
		t.Fatal("group CRUD did not preserve its explicit mutation boundaries")
	}
	accessAssertSafe(t, result)
}

func TestIdentityMutationsNeverConvertOrDeleteAnExternalGroup(t *testing.T) {
	var mutations atomic.Int32
	client := kvTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			mutations.Add(1)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		kvReply(w, accessGroupData("external"))
	})
	ctx := context.Background()
	for _, id := range []string{"", f06GroupID} {
		if _, err := client.WriteGroup(ctx, "selected-token", id, vault.GroupSpec{Name: "app-team"}); err == nil {
			t.Error("group write accepted a known external group")
		}
	}
	if _, err := client.DeleteGroup(ctx, "selected-token", f06GroupID); err == nil {
		t.Error("group delete accepted a known external group")
	}
	if mutations.Load() != 0 {
		t.Error("external group validation happened after its mutation")
	}
}

func TestIdentityCreationWithAnUnknownResultIsNotRetried(t *testing.T) {
	var writes atomic.Int32
	client := kvTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		writes.Add(1)
		kvReply(w, map[string]any{"metadata": "private-f06-missing-identity-id"})
	})
	result, err := client.WriteEntity(context.Background(), "selected-token", "", vault.EntitySpec{Name: "app"})
	if !errors.Is(err, vault.ErrAccessUnconfirmed) || writes.Load() != 1 {
		t.Fatal("identity create without a usable returned ID lost its uncertain outcome")
	}
	accessAssertSafe(t, err)
	accessAssertSafe(t, result)
}

func TestIdentitySpecificationsValidateMembershipBeforeRequests(t *testing.T) {
	entity, err := vault.DecodeEntitySpec(strings.NewReader(`{"name":"app","policies":[],"disabled":true}`))
	if err != nil || entity.Name != "app" || !entity.Disabled || entity.Policies == nil {
		t.Fatal("entity specification did not preserve explicit empty policies")
	}
	group, err := vault.DecodeGroupSpec(strings.NewReader(`{"name":"app-team","policies":[],"member_entity_ids":[],"member_group_ids":[]}`))
	if err != nil || group.MemberEntityIDs == nil || group.MemberGroupIDs == nil {
		t.Fatal("group specification did not preserve explicit empty membership")
	}
	for _, body := range []string{
		`{"name":"app-team","type":"external"}`,
		`{"name":"app-team","member_entity_ids":["private-f06-not-a-uuid"]}`,
		`{"name":"app-team","member_group_ids":null}`,
		`{"name":"app-team","policies":["bad/policy"]}`,
	} {
		if _, err := vault.DecodeGroupSpec(strings.NewReader(body)); err == nil {
			t.Error("group decoder accepted unsupported type, membership or policy fields")
		} else {
			accessAssertSafe(t, err)
		}
	}
	encoded, err := json.Marshal(group)
	if err != nil || strings.Contains(string(encoded), "null") {
		t.Error("empty group configuration lost its explicit replacement lists")
	}
}
