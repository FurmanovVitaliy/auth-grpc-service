package utils

import "time"

// DoWithRetry executes the function fn with retry attempts in case of an error.
// Parameters:
// fn - the function to be executed.
// attempts - the number of execution attempts.
// delay - the delay between attempts.
func DoWithRetry(fn func() error, attempts int, delay time.Duration) (err error) {
	for attempts > 0 {
		if err = fn(); err != nil {

			attempts--
			time.Sleep(delay)
			continue
		}
		return nil
	}
	return err
}
