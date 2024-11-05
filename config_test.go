/*
* Copyright 2022-2024 Thorsten A. Knieling
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*    http://www.apache.org/licenses/LICENSE-2.0
*
 */

package services

import (
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"gopkg.in/yaml.v3"
)

var testStoredXMLData = `<?xml version="1.0" encoding="UTF-8"?>
<ConfigTest>
  <X>
    <Kind>0</Kind>
    <Style>0</Style>
    <Tag></Tag>
    <Value></Value>
    <Anchor></Anchor>
    <HeadComment></HeadComment>
    <LineComment></LineComment>
    <FootComment></FootComment>
    <Line>0</Line>
    <Column>0</Column>
  </X>
  <Ax>abc</Ax>
  <Bx>def</Bx>
  <Cx>
    <Xsub>1</Xsub>
    <Ysub>2</Ysub>
    <SAsub>aa</SAsub>
    <SAsub>bb</SAsub>
  </Cx>
  <Dx>
    <Xsub>2</Xsub>
    <Ysub>3</Ysub>
    <SAsub>ff</SAsub>
    <SAsub>gg</SAsub>
    <CTVsub>
      <Enabled>true</Enabled>
      <Dv>1</Dv>
      <Ev>2</Ev>
    </CTVsub>
  </Dx>
</ConfigTest>`

var testStoredYAMLData = `# Configureation file
x: # LINE
# XYZ

# ABC
ax: abc
bx: def
cx:
  xsub: 1
  ysub: 2
  sasub:
    - aa
    - bb
  machine: null
dx:
  xsub: 2
  ysub: 3
  sasub:
    - ff
    - gg
  machine:
    enabled: true
    dv: 1
    ev: 2
`

var testStoredJSONData = `{
  "X": {
    "Kind": 8,
    "Style": 0,
    "Tag": "",
    "Value": "",
    "Anchor": "",
    "Alias": null,
    "Content": null,
    "HeadComment": "ABC",
    "LineComment": "LINE",
    "FootComment": "XYZ",
    "Line": 0,
    "Column": 0
  },
  "Ax": "abc",
  "Bx": "def",
  "Cx": {
    "Xsub": 1,
    "Ysub": 2,
    "SAsub": [
      "aa",
      "bb"
    ],
    "CTVsub": null
  },
  "Dx": {
    "Xsub": 2,
    "Ysub": 3,
    "SAsub": [
      "ff",
      "gg"
    ],
    "CTVsub": {
      "Enabled": true,
      "Dv": 1,
      "Ev": 2
    }
  }
}
`

// Loader config loader structure calling static configurations
type Loader struct {
}

var loader = &Loader{}

type ConfigTest struct {
	X  yaml.Node
	Ax string
	Bx string
	Cx *ConfigTestSub
	Dx *ConfigTestSub
}

type ConfigTestSub struct {
	Xsub int
	// description: |
	//   Provides machine specific configuration options.
	Ysub  int64
	SAsub []string
	// description: |
	//   Provides cluster specific configuration options.
	CTVsub *ConfigTestValue `yaml:"machine"`
}

type ConfigTestValue struct {
	Enabled bool `yaml:"enabled" head_comment:"Enable or disable." line_comment:"disabled by default"`
	Dv      int
	Ev      int64
}

var config = &ConfigTest{}

// Logging logging configuration
func (loader *Loader) Logging(v interface{}) *Logging {
	return nil
}

// SetLogging set logging configuration
func (loader *Loader) SetLogging(l *Logging) {

}

// Default empty default config
func (loader *Loader) Default() interface{} {
	return config
}

// Current current active config
func (loader *Loader) Current() interface{} {
	return config
}

// IsServer indicate interface to be no server
func (loader *Loader) IsServer() bool {
	return false
}

// Loaded executed after data load
func (loader *Loader) Loaded(nv interface{}) error {
	return nil
}

func TestConfigEvaluateStoreType(t *testing.T) {
	assert.Equal(t, XMLStoreType, evaluateConfigStore("test.xml"))
	assert.Equal(t, YAMLStoreType, evaluateConfigStore("test.yaml"))
	assert.Equal(t, JSONStoreType, evaluateConfigStore("test.json"))
}

func TestConfigXML(t *testing.T) {
	config = &ConfigTest{Ax: "abc", Bx: "def",
		Cx: &ConfigTestSub{1, 2, []string{"aa", "bb"}, nil},
		Dx: &ConfigTestSub{2, 3, []string{"ff", "gg"}, &ConfigTestValue{}},
	}
	storeFileName := fmt.Sprintf("/tmp/test-%d.xml", os.Getpid())
	config.Dx.CTVsub = &ConfigTestValue{true, 1, 2}
	err := StoreConfig(storeFileName, loader)
	if !assert.NoError(t, err) {
		return
	}
	data, err := os.ReadFile(storeFileName)
	if !assert.NoError(t, err) {
		return
	}
	assert.Equal(t, testStoredXMLData, string(data))
	config = &ConfigTest{}
	err = LoadConfig(storeFileName, loader, false)
	if !assert.NoError(t, err) {
		return
	}
	assert.Equal(t, "abc", config.Ax)
	assert.Equal(t, 1, config.Cx.Xsub)
	assert.Equal(t, 1, config.Dx.CTVsub.Dv)
	assert.Equal(t, int64(2), config.Dx.CTVsub.Ev)
}

func TestConfigYAML(t *testing.T) {
	config = &ConfigTest{Ax: "abc", Bx: "def",
		Cx: &ConfigTestSub{1, 2, []string{"aa", "bb"}, nil},
		Dx: &ConfigTestSub{2, 3, []string{"ff", "gg"}, &ConfigTestValue{}},
	}
	storeFileName := fmt.Sprintf("/tmp/test-%d.yaml", os.Getpid())
	config.X.Kind = yaml.ScalarNode
	// config.X.Value = "AA"
	config.X.HeadComment = "ABC"
	config.X.LineComment = "LINE"
	config.X.FootComment = "XYZ"
	config.Dx.CTVsub = &ConfigTestValue{true, 1, 2}
	err := StoreConfig(storeFileName, loader)
	if !assert.NoError(t, err) {
		return
	}
	data, err := os.ReadFile(storeFileName)
	if !assert.NoError(t, err) {
		return
	}
	assert.Equal(t, testStoredYAMLData, string(data))
	config = &ConfigTest{}
	err = LoadConfig(storeFileName, loader, false)
	if !assert.NoError(t, err) {
		return
	}
	assert.Equal(t, "abc", config.Ax)
	assert.Equal(t, 1, config.Cx.Xsub)
	assert.Equal(t, 1, config.Dx.CTVsub.Dv)
	assert.Equal(t, int64(2), config.Dx.CTVsub.Ev)
}

func TestConfigJSON(t *testing.T) {
	config = &ConfigTest{Ax: "abc", Bx: "def",
		Cx: &ConfigTestSub{1, 2, []string{"aa", "bb"}, nil},
		Dx: &ConfigTestSub{2, 3, []string{"ff", "gg"}, &ConfigTestValue{}},
	}
	storeFileName := fmt.Sprintf("/tmp/test-%d.json", os.Getpid())
	config.X.Kind = yaml.ScalarNode
	// config.X.Value = "AA"
	config.X.HeadComment = "ABC"
	config.X.LineComment = "LINE"
	config.X.FootComment = "XYZ"
	config.Dx.CTVsub = &ConfigTestValue{true, 1, 2}
	err := StoreConfig(storeFileName, loader)
	if !assert.NoError(t, err) {
		return
	}
	data, err := os.ReadFile(storeFileName)
	if !assert.NoError(t, err) {
		return
	}
	assert.Equal(t, testStoredJSONData, string(data))
	config = &ConfigTest{}
	err = LoadConfig(storeFileName, loader, false)
	if !assert.NoError(t, err) {
		return
	}
	assert.Equal(t, "abc", config.Ax)
	assert.Equal(t, 1, config.Cx.Xsub)
	assert.Equal(t, 1, config.Dx.CTVsub.Dv)
	assert.Equal(t, int64(2), config.Dx.CTVsub.Ev)
}
