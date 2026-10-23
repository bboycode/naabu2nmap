package cmd

type target struct {
	host  string
	ip    string
	ports map[string]map[int]struct{}
}
