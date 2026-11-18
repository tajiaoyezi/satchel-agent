package channel

import (
	"sync"

	"github.com/satchel/satchel-agent/internal/config"
)

// credStore 并发安全地持有节点当前三把凭据，用于出站认证与双端口 SilentAuth 验证；
// token.rotate 原子写盘成功后再更新这里，确保配置持久化与内存口令一致。
type credStore struct {
	mu         sync.RWMutex
	token      string
	agentToken string
	pullToken  string
}

func newCredStore(tok, agentTok, pullTok string) *credStore {
	return &credStore{
		token:      tok,
		agentToken: agentTok,
		pullToken:  pullTok,
	}
}

func (s *credStore) Token() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.token
}

func (s *credStore) AgentTokens() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.agentToken == "" {
		return nil
	}
	return []string{s.agentToken}
}

func (s *credStore) PullTokens() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.pullToken == "" {
		return nil
	}
	return []string{s.pullToken}
}

func (s *credStore) Apply(token, agentToken, pullToken string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if token != "" {
		s.token = token
	}
	if agentToken != "" {
		s.agentToken = agentToken
	}
	if pullToken != "" {
		s.pullToken = pullToken
	}
}

func (s *credStore) FillConfig(base *config.Config) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	base.Token = s.token
	base.AgentToken = s.agentToken
	base.PullToken = s.pullToken
}
