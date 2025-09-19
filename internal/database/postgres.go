package database

import (
	"database/sql"
	"fmt"
	"time"

	"captcha/internal/config"
	_ "github.com/lib/pq"
)

type DB struct {
	conn *sql.DB
	cfg  *config.Config
}

func NewDB(cfg *config.Config) (*DB, error) {
	dsn := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		cfg.DBHost, cfg.DBPort, cfg.DBUser, cfg.DBPassword, cfg.DBName, cfg.DBSSLMode)

	conn, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	if err := conn.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	db := &DB{
		conn: conn,
		cfg:  cfg,
	}

	if err := db.createTables(); err != nil {
		return nil, fmt.Errorf("failed to create tables: %w", err)
	}

	return db, nil
}

func (db *DB) Close() error {
	return db.conn.Close()
}

func (db *DB) createTables() error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS challenges (
			id VARCHAR(255) PRIMARY KEY,
			salt VARCHAR(255) NOT NULL,
			difficulty INTEGER NOT NULL,
			memory INTEGER NOT NULL,
			threads INTEGER NOT NULL,
			key_len INTEGER NOT NULL,
			target VARCHAR(255) NOT NULL,
			created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
			expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
			solved BOOLEAN NOT NULL DEFAULT FALSE,
			solved_at TIMESTAMP WITH TIME ZONE
		)`,
		`CREATE TABLE IF NOT EXISTS solutions (
			id VARCHAR(255) PRIMARY KEY,
			challenge_id VARCHAR(255) NOT NULL REFERENCES challenges(id),
			nonce VARCHAR(255) NOT NULL,
			hash VARCHAR(255) NOT NULL,
			fingerprint TEXT NOT NULL,
			client_ip VARCHAR(45) NOT NULL,
			user_agent TEXT NOT NULL,
			created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
			valid BOOLEAN NOT NULL DEFAULT FALSE
		)`,
		`CREATE INDEX IF NOT EXISTS idx_challenges_expires_at ON challenges(expires_at)`,
		`CREATE INDEX IF NOT EXISTS idx_challenges_solved ON challenges(solved)`,
		`CREATE INDEX IF NOT EXISTS idx_solutions_challenge_id ON solutions(challenge_id)`,
		`CREATE INDEX IF NOT EXISTS idx_solutions_created_at ON solutions(created_at)`,
	}

	for _, query := range queries {
		if _, err := db.conn.Exec(query); err != nil {
			return fmt.Errorf("failed to execute query: %s, error: %w", query, err)
		}
	}

	return nil
}

func (db *DB) CreateChallenge(challenge *Challenge) error {
	query := `INSERT INTO challenges (id, salt, difficulty, memory, threads, key_len, target, created_at, expires_at)
			  VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`
	
	_, err := db.conn.Exec(query, challenge.ID, challenge.Salt, challenge.Difficulty,
		challenge.Memory, challenge.Threads, challenge.KeyLen, challenge.Target,
		challenge.CreatedAt, challenge.ExpiresAt)
	
	return err
}

func (db *DB) GetChallenge(id string) (*Challenge, error) {
	query := `SELECT id, salt, difficulty, memory, threads, key_len, target, created_at, expires_at, solved, solved_at
			  FROM challenges WHERE id = $1`
	
	challenge := &Challenge{}
	err := db.conn.QueryRow(query, id).Scan(
		&challenge.ID, &challenge.Salt, &challenge.Difficulty, &challenge.Memory,
		&challenge.Threads, &challenge.KeyLen, &challenge.Target, &challenge.CreatedAt,
		&challenge.ExpiresAt, &challenge.Solved, &challenge.SolvedAt,
	)
	
	if err == sql.ErrNoRows {
		return nil, nil
	}
	
	return challenge, err
}

func (db *DB) MarkChallengeSolved(id string) error {
	query := `UPDATE challenges SET solved = true, solved_at = NOW() WHERE id = $1`
	_, err := db.conn.Exec(query, id)
	return err
}

func (db *DB) CreateSolution(solution *Solution) error {
	query := `INSERT INTO solutions (id, challenge_id, nonce, hash, fingerprint, client_ip, user_agent, created_at, valid)
			  VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`
	
	_, err := db.conn.Exec(query, solution.ID, solution.ChallengeID, solution.Nonce,
		solution.Hash, solution.Fingerprint, solution.ClientIP, solution.UserAgent,
		solution.CreatedAt, solution.Valid)
	
	return err
}

func (db *DB) GetSolution(id string) (*Solution, error) {
	query := `SELECT id, challenge_id, nonce, hash, fingerprint, client_ip, user_agent, created_at, valid
			  FROM solutions WHERE id = $1`
	
	solution := &Solution{}
	err := db.conn.QueryRow(query, id).Scan(
		&solution.ID, &solution.ChallengeID, &solution.Nonce, &solution.Hash,
		&solution.Fingerprint, &solution.ClientIP, &solution.UserAgent,
		&solution.CreatedAt, &solution.Valid,
	)
	
	if err == sql.ErrNoRows {
		return nil, nil
	}
	
	return solution, err
}

func (db *DB) CleanupExpiredChallenges() error {
	query := `DELETE FROM challenges WHERE expires_at < NOW() AND solved = false`
	_, err := db.conn.Exec(query)
	return err
}

func (db *DB) CleanupOldSolutions(olderThan time.Duration) error {
	query := `DELETE FROM solutions WHERE created_at < $1`
	cutoff := time.Now().Add(-olderThan)
	_, err := db.conn.Exec(query, cutoff)
	return err
} 