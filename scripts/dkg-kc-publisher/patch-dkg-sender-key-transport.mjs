#!/usr/bin/env node
import { readFileSync, writeFileSync } from 'node:fs';

const file = process.argv[2];
if (!file) throw new Error('usage: node patch-dkg-sender-key-transport.mjs /path/to/dkg-agent-crypto.js');

let source = readFileSync(file, 'utf8');
let changed = false;
const transportMarker = 'queued after retryable transport failure';

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

if (!source.includes(transportMarker)) {
  const occurrences = source.split(before).length - 1;
  if (occurrences !== 1) throw new Error(`expected one sender-key transport catch block in ${file}, found ${occurrences}`);
  source = source.replace(before, after);
  changed = true;
}

const rejectionMarker = "reasonCode === 'not-agent-gated'";
const rejectionBefore = `        return SWM_SENDER_KEY_PACKAGE_ACK_RETRYABLE_REASON_CODES.includes(reasonCode);
`;
const rejectionAfter = `        return SWM_SENDER_KEY_PACKAGE_ACK_RETRYABLE_REASON_CODES.includes(reasonCode)
            || reasonCode === 'not-agent-gated';
`;

if (!source.includes(rejectionMarker)) {
  const occurrences = source.split(rejectionBefore).length - 1;
  if (occurrences !== 1) throw new Error(`expected one sender-key retryable ACK check in ${file}, found ${occurrences}`);
  source = source.replace(rejectionBefore, rejectionAfter);
  changed = true;
}

if (changed) {
  writeFileSync(file, source);
  process.stdout.write(`patched retryable sender-key transport and ACK handling: ${file}\n`);
} else {
  process.stdout.write(`sender-key transport and ACK patch already present: ${file}\n`);
}
