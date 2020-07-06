package auth

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"os"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
)

func TestMain(m *testing.M) {
	log.SetFlags(log.Lshortfile | log.LstdFlags)
	os.Exit(m.Run())
}

func TestNew(t *testing.T) {
	x := New(nil)
	t.Run("Should have empty rules", func(t *testing.T) {
		assert.NotNil(t, x.rules)
	})
}

func TestSeedData(t *testing.T) {
	t.Run("seed data successfully", func(t *testing.T) {
		assert.Nil(t, SeedData("testdata/pritunl_data.json"))
		assert.NotNil(t, store)
		assert.Equal(t, 3, len(store.secrets))
	})
}

func TestVerify(t *testing.T) {
	var rc RulesConf
	rcBytes, err := ioutil.ReadFile("testdata/rules.json")
	assert.Nil(t, err)

	assert.Nil(t, json.Unmarshal(rcBytes, &rc))

	x := New(&rc)
	t.Run("fail for nil paylod", func(t *testing.T) {
		valid, err := x.Verify(nil)
		assert.False(t, valid, "Validation should fail")
		assert.NotNil(t, err)
	})

	t.Run("fail for missing email and invalid secret otp", func(t *testing.T) {
		p := NewPayload("test", "key1", "", "", "12345", true, true)
		valid, err := x.Verify(p)
		assert.False(t, valid)
		assert.NotNil(t, err)
	})

	t.Run("fail for missing key with invalid OTP", func(t *testing.T) {
		p := NewPayload("test", "missing", "", "", "12345", true, true)
		valid, err := x.Verify(p)
		assert.False(t, valid)
		assert.NotNil(t, err)
	})

	t.Run("pass for missing email and otp but whitelisted IP", func(t *testing.T) {
		p := NewPayload("foo", "missing", "1.1.1.1", "", "", false, true)
		valid, err := x.Verify(p)
		assert.True(t, valid)
		assert.Nil(t, err)
	})

	t.Run("fail for missing email and otp but whitelisted IP and required otp", func(t *testing.T) {
		p := NewPayload("foo", "missing", "1.1.1.1", "", "", true, true)
		valid, err := x.Verify(p)
		assert.False(t, valid)
		assert.NotNil(t, err)
	})

	t.Run("pass for wrong email and otp but whitelisted IP", func(t *testing.T) {
		p := NewPayload("foo", "missing", "1.1.1.1", "missing@trustingsocial.com", "12345",
			false, true)
		valid, err := x.Verify(p)
		assert.True(t, valid)
		assert.Nil(t, err)
	})

	t.Run("pass for admin email with valid otp for any resource", func(t *testing.T) {
		otp, err := totp.GenerateCode("GMYDQN3GGVRWIY3CMNQWINLFGE3DQOJUHFRDOM3DHBSWEZDGGVRA", time.Now())
		assert.Nil(t, err)

		p := NewPayload("foo", "missing", "", "admin@trustingsocial.com", otp, true, true)
		valid, err := x.Verify(p)
		assert.True(t, valid)
		assert.Nil(t, err)
	})

	t.Run("pass for shared resource with any valid email and otp", func(t *testing.T) {
		otp, err := totp.GenerateCode("7VP7X6OC37YVIRVI", time.Now())
		assert.Nil(t, err)
		p := NewPayload("shared", "POST", "", "abc@trustingsocial.com", otp, true, true)
		valid, err := x.Verify(p)
		assert.True(t, valid)
		assert.Nil(t, err)
	})
}
