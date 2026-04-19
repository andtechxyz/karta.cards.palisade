// Admin barrel — Program CRUD + NDEF template rendering.  Tier rules and
// currency live on Vera's TokenisationProgram (see @vera/programs), so this
// barrel covers card-domain program operations only.

export { programTypeSchema } from '@palisade/card-programs';
export type { ProgramType } from '@palisade/card-programs';

export {
  createProgram,
  getProgram,
  listPrograms,
  resolveNdefUrlsByCardRef,
  resolveNdefUrlsForCard,
  updateProgram,
} from './program.service.js';
export type { UpsertProgramInput, ListProgramsOptions } from './program.service.js';

export { renderNdefUrls, validateNdefUrlTemplate } from './ndef.js';
export type { NdefUrlPair } from './ndef.js';
