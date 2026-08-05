@{
    Severity     = @('Error', 'Warning')
    ExcludeRules = @(
        # Collectors share a uniform Param() surface for orchestration.
        # Unused switches on a given collector are intentional interface consistency.
        'PSReviewUnusedParameter'
    )
}
