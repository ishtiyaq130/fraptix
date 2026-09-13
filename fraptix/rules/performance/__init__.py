from .query_inside_loop import QueryInsideLoopRule
from .query_repeated import RepeatedDatabaseQueryRule
from .get_doc_inside_loop import GetDocInsideLoopRule
from .get_doc_repeated import RepeatedGetDocRule
from .redundant_retrieval import RedundantDatabaseRetrievalRule
from .unbounded_retrieval import UnboundedDatabaseRetrievalRule
from .exists_before_get_doc import ExistsBeforeGetDocRule

def get_rules():
    return [
        QueryInsideLoopRule(),
        RepeatedDatabaseQueryRule(),
        GetDocInsideLoopRule(),
        RepeatedGetDocRule(),
        RedundantDatabaseRetrievalRule(),
        UnboundedDatabaseRetrievalRule(),
        ExistsBeforeGetDocRule(),
    ]