package main

import (
	"encoding/json"
	"time"
)

// Event represents a generic event interface
type Event interface {
	GetType() string
	GetTimestamp() int64
}

// BaseEvent provides common fields for all events
type BaseEvent struct {
	Type      string `json:"type"`
	Timestamp int64  `json:"timestamp"`
}

// GetType returns the event type
func (e *BaseEvent) GetType() string {
	return e.Type
}

// GetTimestamp returns the event timestamp
func (e *BaseEvent) GetTimestamp() int64 {
	return e.Timestamp
}

// ParseEvent parses a JSON event into the appropriate event type
func ParseEvent(data []byte) (Event, error) {
	var base BaseEvent
	if err := json.Unmarshal(data, &base); err != nil {
		return nil, err
	}

	switch base.Type {
	case "keep-alive":
		var event KeepAliveEvent
		if err := json.Unmarshal(data, &event); err != nil {
			return nil, err
		}
		return &event, nil
	case "endpoint":
		var event EndpointEvent
		if err := json.Unmarshal(data, &event); err != nil {
			return nil, err
		}
		return &event, nil
	default:
		// Return the base event for unknown types
		return &base, nil
	}
}

// KeepAliveEvent represents a keep-alive event with no data
type KeepAliveEvent struct {
	Type      string `json:"type"`
	Timestamp int64  `json:"timestamp"`
}

// GetType returns the event type
func (e *KeepAliveEvent) GetType() string {
	return e.Type
}

// GetTimestamp returns the event timestamp
func (e *KeepAliveEvent) GetTimestamp() int64 {
	return e.Timestamp
}

// NewKeepAliveEvent creates a new keep-alive event
func NewKeepAliveEvent() *KeepAliveEvent {
	return &KeepAliveEvent{
		Type:      "keep-alive",
		Timestamp: time.Now().Unix(),
	}
}

// IsKeepAlive returns true if this is a keep-alive event
func (e *KeepAliveEvent) IsKeepAlive() bool {
	return e.Type == "keep-alive"
}

// EndpointEvent represents an endpoint event containing the endpoint URL
type EndpointEvent struct {
	Type      string `json:"type"`
	Endpoint  string `json:"endpoint"`
	Timestamp int64  `json:"timestamp"`
}

// GetType returns the event type
func (e *EndpointEvent) GetType() string {
	return e.Type
}

// GetTimestamp returns the event timestamp
func (e *EndpointEvent) GetTimestamp() int64 {
	return e.Timestamp
}

// NewEndpointEvent creates a new endpoint event
func NewEndpointEvent(endpoint string) *EndpointEvent {
	return &EndpointEvent{
		Type:      "endpoint",
		Endpoint:  endpoint,
		Timestamp: time.Now().Unix(),
	}
}

// IsEndpoint returns true if this is an endpoint event
func (e *EndpointEvent) IsEndpoint() bool {
	return e.Type == "endpoint"
}

// GetEndpoint returns the endpoint URL from the event
func (e *EndpointEvent) GetEndpoint() string {
	return e.Endpoint
}
