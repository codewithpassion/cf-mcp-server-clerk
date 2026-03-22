export interface ServerConfig {
	command: string;
	args: string[];
	env?: Record<string, string>;
}
