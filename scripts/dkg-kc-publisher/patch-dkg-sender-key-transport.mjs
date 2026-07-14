#!/usr/bin/env node
import { readFileSync, writeFileSync } from 'node:fs';

const file = process.argv[2];
if (!file) throw new Error('usage: node patch-dkg-sender-key-transport.mjs /path/to/dkg-agent-crypto.js');

const source = readFileSync(file, 'utf8');
const marker = 'queued after retryable transport failure';
if (source.includes(marker)) {
  process.stdout.write(`sender-key transport patch already present: ${file}\n`);
  process.exit(0);
}

const before = `            catch (err) {
                return {
                    kind: 'failure',
                    agentAddress: recipientAgentAddress,
                    keyId: recipient.recipientKeyId,
                    error: err instanceof Error ? err : new Error(String(err)),
                };
            }
`;

const after = `            catch (err) {
                const error = err instanceof Error ? err : new Error(String(err));
                const retryableTransportFailure = /(Network identity probe failed|send timeout elapsed|operation was aborted due to timeout|connection gater denied|no valid addresses|dial request)/i.test(error.message);
                if (retryableTransportFailure) {
                    const messageId = this.swmSenderKeyPackageMessageId(packageBytes);
                    this.enqueuePendingSenderKey({
                        senderAgentAddress: senderAgentAddress.toLowerCase(),
                        recipientAgentAddress: recipientAgentAddress.toLowerCase(),
                        recipientKeyId: recipient.recipientKeyId,
                        epochId: state.epochId,
                        contextGraphId: state.contextGraphId,
                        subGraphName: state.subGraphName,
                        packageBytes,
                        messageId,
                        createdAtMs: Date.now(),
                    });
                    pendingSenderKeyQueued = true;
                    this.log.warn(input.ctx, \`SWM sender-key setup for \${recipientAgentAddress} keyId=\${recipient.recipientKeyId} \` +
                        \`queued after retryable transport failure: \${error.message} — recipient will receive on next reconnect\`);
                    return { kind: 'success', agentAddress: recipientAgentAddress };
                }
                return {
                    kind: 'failure',
                    agentAddress: recipientAgentAddress,
                    keyId: recipient.recipientKeyId,
                    error,
                };
            }
`;

const occurrences = source.split(before).length - 1;
if (occurrences !== 1) throw new Error(`expected one sender-key transport catch block in ${file}, found ${occurrences}`);
writeFileSync(file, source.replace(before, after));
process.stdout.write(`patched retryable sender-key transport handling: ${file}\n`);
