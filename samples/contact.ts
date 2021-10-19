import { Database, Transaction } from '@google-cloud/spanner';

@Injectable()
export class ContractEffectAssetRepository {
  constructor(private readonly spannerDb: ContractDatabase) {}

  private async selectContractById(
    select: string[],
    contractId: string | string[],
    spannerTransaction: Transaction | Database = this.spannerDb
  ) {
    if ((contractId || []).length === 0) {
      return [];
    }

    const [rows] = await spannerTransaction.run({
      sql:
        "SELECT * FROM Contact WHERE contactId IN UNNEST %s AND active "
      params: {
        filtersIds: arrayWrapper(contractId),
      },
    });

    return rows.map((r) => r.toJSON());
  }
}
