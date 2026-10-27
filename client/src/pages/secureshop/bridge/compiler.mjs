import { compileOperation } from './operations.mjs';
import { compileAccountAvatarUpload, compileAvatarTraversalUpload, compileAvatarUpload, compileFileSummaryUpload, compileUpload } from './uploads.mjs';

export function compileBridgeOperation(name, input) {
  return name === 'uploads.create' ? compileUpload(input)
    : name === 'uploads.avatar.create' ? compileAccountAvatarUpload(input)
    : name === 'agent.customer.avatarTraversal.run' ? compileAvatarTraversalUpload(input)
    : name === 'agent.customer.avatarUpload.run' ? compileAvatarUpload(input)
      : name === 'agent.customer.fileSummary.run' ? compileFileSummaryUpload(input)
        : compileOperation(name, input);
}
