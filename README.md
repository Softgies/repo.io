# Clean Architecture & CQRS Pattern Implementation Guide

**Version:** 1.0  
**Platform:** .NET 9  
**Architecture Pattern:** Clean Architecture + CQRS (Command Query Responsibility Segregation)  
**Last Updated:** 2024

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Architectural Principles](#architectural-principles)
3. [Layered Architecture Breakdown](#layered-architecture-breakdown)
4. [Project Structure & Responsibilities](#project-structure--responsibilities)
5. [CQRS Pattern Implementation](#cqrs-pattern-implementation)
6. [Dependency Management & Injection](#dependency-management--injection)
7. [Complete Request Lifecycle](#complete-request-lifecycle)
8. [Cross-Cutting Concerns](#cross-cutting-concerns)
9. [Testing & Testability](#testing--testability)
10. [Architectural Benefits & Trade-offs](#architectural-benefits--trade-offs)

---

## Executive Summary

### System Architecture Overview

This solution implements **Clean Architecture** with **CQRS (Command Query Responsibility Segregation)** patterns, built on .NET 9. The architecture emphasizes:

- **Separation of Concerns**: Each layer has a single, well-defined responsibility
- **Dependency Inversion**: Dependencies point inward, never outward
- **Testability**: Core business logic isolated from infrastructure concerns
- **Scalability**: Independent read/write model optimization
- **Maintainability**: Clear folder structure and naming conventions

### High-Level System Architecture

```
???????????????????????????????????????????????????????????????
?                  CLIENT APPLICATIONS                        ?
?     (Web / Mobile / Third-party API Consumers)              ?
???????????????????????????????????????????????????????????????
                     ?
         ??????????????????????????
         ?                        ?
    ?????????????          ????????????????
    ? REST API  ?          ?  API Gateway ?
    ? (Port)    ?          ?  (Optional)  ?
    ?????????????          ????????????????
         ?                       ?
         ?????????????????????????
                     ?
        ???????????????????????????
        ?  API Presentation Layer ?
        ?  (Controllers)          ?
        ?  (Middlewares)          ?
        ?  (Helpers)              ?
        ???????????????????????????
                     ?
        ???????????????????????????????????
        ? Application Layer (Orchestration)?
        ?  ?? Commands (Write)            ?
        ?  ?? Queries (Read)              ?
        ?  ?? Handlers                    ?
        ?  ?? Validators                  ?
        ?  ?? Behaviors (Pipeline)        ?
        ?  ?? DTOs                        ?
        ?  ?? Interfaces (Abstractions)   ?
        ???????????????????????????????????
                     ?
        ?????????????????????????????????????
        ? Infrastructure Layer (Implementation)
        ?  ?? Repositories                 ?
        ?  ?? Services                     ?
        ?  ?? DbContext (EF Core 9)        ?
        ?  ?? Entity Configurations        ?
        ?  ?? External Integrations        ?
        ?????????????????????????????????????
                     ?
        ???????????????????????????????????
        ?  Domain Layer (Business Rules)  ?
        ?  ?? Entities                    ?
        ?  ?? Value Objects               ?
        ?  ?? Constants & Enums           ?
        ?  ?? Domain Interfaces           ?
        ???????????????????????????????????
                     ?
        ?????????????????????????????????????
        ?  Data Persistence & External Sys  ?
        ?  ?? SQL Server Database          ?
        ?  ?? Redis Cache                  ?
        ?  ?? Message Queues               ?
        ?  ?? Third-party Services         ?
        ?????????????????????????????????????
```

### Key Architectural Characteristics

| Characteristic | Benefit | Implementation |
|---|---|---|
| **Clean Architecture** | Testable, flexible, independent of frameworks | Strict layering with inward dependencies |
| **CQRS** | Optimized read/write paths, scalability | Separate command and query models |
| **Dependency Injection** | Loose coupling, flexibility | Constructor injection, DI container |
| **MediatR Pipeline** | Centralized request handling, extensibility | Behaviors for cross-cutting concerns |
| **Async/Await** | Better resource utilization | Async throughout all layers |
| **Repository Pattern** | Data access abstraction | Interface-based repository contracts |

---

## Architectural Principles

### 1. **The Dependency Rule** (Foundation of Clean Architecture)

**Core Principle**: Dependencies always point inward. Outer layers depend on inner layers, **never the reverse**.

```
???????????????????????????????????????????
?           OUTER LAYERS                  ?
?  - API Controllers                      ?
?  - Infrastructure Services              ?
?  - Database Access                      ?
?  - External Integrations                ?
???????????????????????????????????????????
                 ?
        ????????????????????
        ?    DEPENDS ON    ?
        ?     (Points In)  ?
        ????????????????????
                 ?
???????????????????????????????????????????
?          INNER LAYERS                   ?
?  - Application Use Cases                ?
?  - Domain Business Rules                ?
?  - Constants & Enums                    ?
?  - Domain Entities & Value Objects      ?
???????????????????????????????????????????

DEPENDENCY DIRECTION: ? ? ? Inward Only
```

**Implications:**

- **Domain Layer** (innermost): Zero external dependencies. Pure C# classes.
- **Application Layer**: Depends only on Domain. Contains interfaces for infrastructure.
- **Infrastructure Layer**: Implements Application interfaces. Depends on both Application and Domain.
- **API Layer** (outermost): Depends on all layers. Orchestrates request flow.

**Violation Prevention:**

```csharp
// ? WRONG - Infrastructure depends on API layer
public class SomeService
{
    private readonly IHttpClientFactory _httpClient;  // ? API concern leaking in
}

// ? CORRECT - Only abstractions, no concrete dependencies
public class SomeService(IExternalDataProvider provider)
{
    private readonly IExternalDataProvider _provider;  // ? Interface defined in Application layer
}
```

### 2. **CQRS Pattern** (Separation of Read and Write)

**Principle**: Separate the application's **write operations (Commands)** from **read operations (Queries)**.

```
????????????????????????
?   User/Client        ?
????????????????????????
         ?
    ????????????????????????????
    ?                           ?
    ? (Write/Modify)       (Read)
    ?                           ?
    ?                           ?
???????????????         ????????????????
?  Commands   ?         ?   Queries    ?
?             ?         ?              ?
? - Create    ?         ? - Get All    ?
? - Update    ?         ? - Get By ID  ?
? - Delete    ?         ? - Search     ?
? - Execute   ?         ? - Report     ?
???????????????         ????????????????
       ?                       ?
       ? (IRequestHandler)     ? (IRequestHandler)
       ?                       ?
???????????????         ?????????????????
? Handlers    ?         ? Handlers      ?
?             ?         ?               ?
? Validate    ?         ? Read Only     ?
? Modify DB   ?         ? No Side-fx    ?
? Cache Clear ?         ? Cache Friendly
???????????????         ?????????????????
       ?                       ?
       ?                       ?
????????????????????????????????????????
?   Result<T>                          ?
? { IsSuccess, Data, Error }           ?
????????????????????????????????????????
```

**Key Advantages:**

- **Optimization**: Write and read models can be optimized independently
- **Scalability**: Read-heavy systems can scale query side separately
- **Clarity**: Intent is explicit (Command = mutation, Query = read-only)
- **Testability**: Each handler has single responsibility

### 3. **Inversion of Control (IoC) & Dependency Injection**

**Principle**: Dependencies are injected, not created.

```csharp
// ? WRONG - Service locator anti-pattern
public class SomeHandler
{
    public void Process()
    {
        var repo = ServiceLocator.GetService<IRepository>();  // ? Bad
    }
}

// ? CORRECT - Constructor injection
public class SomeHandler(IRepository repository, ILogger logger)
{
    private readonly IRepository _repository = repository;
    private readonly ILogger _logger = logger;
    
    public void Process()
    {
        // Dependencies ready to use
    }
}

// ? ALSO CORRECT - Property injection (when needed)
public class SomeHandler
{
    public IRepository Repository { get; set; }
}
```

**Service Lifetime Management:**

```csharp
// Transient: New instance every time (stateless helpers)
services.AddTransient<IStatelessUtility, StatelessUtility>();

// Scoped: One per HTTP request (DbContext, handlers)
services.AddScoped<IRepository, Repository>();
services.AddScoped<ApplicationDbContext>();

// Singleton: One for entire application (expensive to create)
services.AddSingleton<IConfiguration>(configuration);
services.AddSingleton<ICache, MemoryCache>();
```

---

## Layered Architecture Breakdown

### Overview: The Five Layers

```
??????????????????????????????????????????????????????????????????????
? LAYER 5: PRESENTATION (API Layer)                                  ?
? ?? Controllers: HTTP endpoint handlers                             ?
? ?? Middlewares: Request/response pipeline                          ?
? ?? Helpers: API-specific utilities (auth, paths, localization)    ?
? ?? Configuration: API service registration                         ?
?                                                                     ?
? Dependencies: Application + Infrastructure + Domain               ?
? Framework: ASP.NET Core                                            ?
? Language: C# 13 / .NET 9                                           ?
??????????????????????????????????????????????????????????????????????
                              ? Depends On
                              ?
??????????????????????????????????????????????????????????????????????
? LAYER 4: APPLICATION (Use Case Orchestration)                      ?
? ?? Commands: Write operation requests                              ?
? ?? Queries: Read operation requests                                ?
? ?? Handlers: MediatR request handlers                              ?
? ?? Validators: FluentValidation validators                         ?
? ?? Behaviors: Pipeline middleware (validation, logging, etc.)      ?
? ?? DTOs: Data transfer objects                                     ?
? ?? Interfaces: Abstractions for infrastructure                     ?
? ?? Configuration: Application service registration                 ?
?                                                                     ?
? Dependencies: Domain only                                          ?
? Framework: MediatR, FluentValidation                               ?
? Responsibility: Business logic orchestration                       ?
??????????????????????????????????????????????????????????????????????
                              ? Depends On
                              ?
??????????????????????????????????????????????????????????????????????
? LAYER 3: INFRASTRUCTURE (Implementation)                            ?
? ?? Repositories: Data access abstractions (implementation)          ?
? ?? Services: External system integrations                           ?
? ?? DbContext: EF Core data context                                 ?
? ?? Configurations: Entity mappings                                  ?
? ?? Data: Database-specific code                                    ?
?                                                                     ?
? Dependencies: Application + Domain                                 ?
? Framework: EF Core 9, external libraries                           ?
? Responsibility: Data persistence, external integrations            ?
??????????????????????????????????????????????????????????????????????
                              ? Depends On
                              ?
??????????????????????????????????????????????????????????????????????
? LAYER 2: DOMAIN (Business Rules)                                   ?
? ?? Entities: Core business objects                                 ?
? ?? Value Objects: Immutable, no identity                           ?
? ?? Constants: Business rule constants                              ?
? ?? Enums: Enumeration types                                        ?
? ?? Interfaces: Domain service contracts                            ?
?                                                                     ?
? Dependencies: NONE (framework-independent)                         ?
? Framework: Pure C# / .NET                                          ?
? Responsibility: Core business logic (most stable)                  ?
??????????????????????????????????????????????????????????????????????
                              ? Depends On
                              ?
??????????????????????????????????????????????????????????????????????
? LAYER 1: RESOURCES (Static Assets & Localization)                  ?
? ?? Localization: Multi-language string resources                   ?
? ?? Constants: Shared string resources                              ?
? ?? Static Assets: Configuration templates                          ?
?                                                                     ?
? Dependencies: Domain (shared)                                      ?
? Responsibility: Localization & static resources                    ?
??????????????????????????????????????????????????????????????????????
```

### Layer Characteristics Matrix

| Layer | Stability | Testability | Changeability | Dependencies | Primary Focus |
|-------|-----------|-------------|--------------|--------------|--------------|
| **API** | Low | Medium | High | All layers | HTTP semantics |
| **Application** | Medium | High | Medium | Domain only | Use cases |
| **Infrastructure** | Low | Medium | High | App + Domain | External systems |
| **Domain** | High | High | Low | None | Business rules |
| **Resources** | High | Low | Low | Shared | Localization |

---

## Project Structure & Responsibilities

### Project 1: Domain Layer (e.g., `CompanyName.Domain`)

**Purpose**: Core business logic, entities, and rules. **Zero external dependencies.**

#### Folder Structure

```
CompanyName.Domain/
??? Entities/
?   ??? User.cs                    # Primary entity
?   ??? Order.cs                   # Primary entity
?   ??? OrderItem.cs               # Sub-entity
?   ??? ... (more entities)
??? ValueObjects/
?   ??? Money.cs                   # Immutable value object
?   ??? Address.cs                 # Immutable value object
?   ??? Email.cs                   # Immutable value object
??? Constants/
?   ??? RoleNames.cs               # Role constants
?   ??? ValidationRules.cs         # Validation constants
?   ??? BusinessRules.cs           # Business rule constants
?   ??? ErrorMessages.cs           # Standard error messages
??? Enums/
?   ??? OrderStatus.cs             # Order state enum
?   ??? UserRole.cs                # Role enum
?   ??? PaymentMethod.cs           # Payment type enum
??? Interfaces/
?   ??? IDomainService.cs          # Domain service contracts (rare)
??? GlobalUsing.Domain.cs          # Shared using statements
```

#### Key Characteristics

**Anemic vs. Rich Models**:
```csharp
// ? Anemic (Anti-pattern): Data container only
public class User
{
    public int Id { get; set; }
    public string Name { get; set; }
    public string Email { get; set; }
}

// ? Rich Domain Model: Encapsulates behavior
public class User
{
    public int Id { get; private set; }
    public string Name { get; private set; }
    public Email Email { get; private set; }
    
    // Business logic encapsulated
    public void ChangeEmail(Email newEmail)
    {
        if (newEmail == null)
            throw new ArgumentNullException(nameof(newEmail));
        
        Email = newEmail;
    }
    
    public bool IsAdministrator => Role == UserRole.Admin;
}
```

**Entity Definition Example**:

```csharp
// Domain entity with clear responsibilities
public class Order
{
    // Primary key
    public int Id { get; private set; }
    
    // Value objects
    public Money TotalAmount { get; private set; }
    public Address ShippingAddress { get; private set; }
    
    // Entity references (foreign keys)
    public int UserId { get; private set; }
    public User User { get; private set; }
    
    // Collections
    public ICollection<OrderItem> Items { get; private set; } = new List<OrderItem>();
    
    // Audit fields
    public DateTime CreatedAt { get; private set; }
    public DateTime? UpdatedAt { get; private set; }
    
    // State management
    public OrderStatus Status { get; private set; }
    
    // Business methods (domain logic)
    public void Cancel()
    {
        if (Status != OrderStatus.Pending)
            throw new InvalidOperationException("Only pending orders can be cancelled");
        
        Status = OrderStatus.Cancelled;
        UpdatedAt = DateTime.UtcNow;
    }
}
```

**Entity Characteristics**:
- ? No framework dependencies (no using EF Core, no attributes from infrastructure)
- ? Encapsulated state (private setters)
- ? Business logic methods
- ? Validation in constructors or methods
- ? Immutable value objects for data integrity

#### Constraints & Rules

1. **No Infrastructure Dependencies**: Never reference DbContext, HttpClient, or other infrastructure
2. **No Framework Attributes**: Don't use `[Column]`, `[Required]`, etc. (EF Core configuration belongs in Infrastructure)
3. **Pure C# Classes**: Should compile and run without any external packages
4. **Most Stable Layer**: Changes here ripple through entire system - be very deliberate

#### Testing Domain Layer

```csharp
[TestFixture]
public class UserTests
{
    [Test]
    public void ChangeEmail_WithValidEmail_UpdatesEmailSuccessfully()
    {
        // Arrange
        var user = new User("John", Email.Create("john@example.com"));
        var newEmail = Email.Create("john.doe@example.com");
        
        // Act
        user.ChangeEmail(newEmail);
        
        // Assert
        Assert.That(user.Email, Is.EqualTo(newEmail));
    }
    
    [Test]
    public void ChangeEmail_WithNullEmail_ThrowsException()
    {
        // Arrange
        var user = new User("John", Email.Create("john@example.com"));
        
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => user.ChangeEmail(null));
    }
}
```

---

### Project 2: Application Layer (e.g., `CompanyName.Application`)

**Purpose**: Use case orchestration, CQRS implementation, business logic coordination.

**Dependency**: Domain only (never references Infrastructure directly)

#### Folder Structure

```
CompanyName.Application/
??? Features/
?   ??? Users/
?   ?   ??? Commands/
?   ?   ?   ??? CreateUser/
?   ?   ?   ?   ??? CreateUserCommand.cs
?   ?   ?   ?   ??? CreateUserCommandHandler.cs
?   ?   ?   ?   ??? CreateUserCommandValidator.cs
?   ?   ?   ??? UpdateUser/
?   ?   ?   ?   ??? UpdateUserCommand.cs
?   ?   ?   ?   ??? UpdateUserCommandHandler.cs
?   ?   ?   ?   ??? UpdateUserCommandValidator.cs
?   ?   ?   ??? DeleteUser/
?   ?   ?       ??? DeleteUserCommand.cs
?   ?   ?       ??? DeleteUserCommandHandler.cs
?   ?   ??? Queries/
?   ?   ?   ??? GetAllUsers/
?   ?   ?   ?   ??? GetAllUsersQuery.cs
?   ?   ?   ?   ??? GetAllUsersQueryHandler.cs
?   ?   ?   ??? GetUserById/
?   ?   ?   ?   ??? GetUserByIdQuery.cs
?   ?   ?   ?   ??? GetUserByIdQueryHandler.cs
?   ?   ?   ??? SearchUsers/
?   ?   ?       ??? SearchUsersQuery.cs
?   ?   ?       ??? SearchUsersQueryHandler.cs
?   ?   ??? Results/
?   ?       ??? UserResult.cs
?   ?       ??? UserDetailResult.cs
?   ??? Orders/
?   ?   ??? Commands/
?   ?   ?   ??? CreateOrder/
?   ?   ??? Queries/
?   ?       ??? GetOrdersById/
?   ??? ... (other features)
??? Common/
?   ??? Behaviors/
?   ?   ??? ValidationBehavior.cs
?   ?   ??? LoggingBehavior.cs
?   ?   ??? TransactionBehavior.cs
?   ?   ??? PerformanceMonitoringBehavior.cs
?   ??? Response/
?   ?   ??? Result.cs
?   ?   ??? Error.cs
?   ?   ??? ValidationError.cs
?   ?   ??? PagedResult.cs
?   ??? Localization/
?   ?   ??? Localization.cs
?   ?   ??? LocalizationKeys.cs
?   ??? Settings/
?   ?   ??? ApplicationSettings.cs
?   ?   ??? JwtSettings.cs
?   ?   ??? CacheSettings.cs
?   ??? Extensions/
?       ??? StringExtensions.cs
?       ??? DateTimeExtensions.cs
??? Interfaces/
?   ??? Repositories/
?   ?   ??? IBaseRepository.cs
?   ?   ??? IUserRepository.cs
?   ?   ??? IOrderRepository.cs
?   ?   ??? ... (one per aggregate root)
?   ??? Services/
?   ?   ??? IEmailService.cs
?   ?   ??? IFileStorageService.cs
?   ?   ??? IAuthenticationService.cs
?   ?   ??? ICacheService.cs
?   ?   ??? ... (service contracts)
?   ??? Identity/
?       ??? ICurrentUserService.cs
?       ??? ITokenService.cs
??? DTOs/
?   ??? UserDto.cs
?   ??? CreateUserDto.cs
?   ??? ... (data transfer objects)
??? Mappings/
?   ??? UserMappingProfile.cs
?   ??? ... (AutoMapper profiles)
??? ApplicationServiceRegistration.cs
??? AssemblyReference.cs
??? GlobalUsing.Application.cs
```

#### CQRS Command Implementation

```csharp
// 1. Command Definition
public sealed class CreateUserCommand : IRequest<Result<UserResult>>
{
    public string FirstName { get; set; } = null!;
    public string LastName { get; set; } = null!;
    public string Email { get; set; } = null!;
    public string Password { get; set; } = null!;
}

// 2. Validator
public class CreateUserCommandValidator : AbstractValidator<CreateUserCommand>
{
    public CreateUserCommandValidator()
    {
        RuleFor(x => x.FirstName)
            .NotEmpty().WithMessage("First name is required")
            .MaximumLength(100).WithMessage("First name cannot exceed 100 characters");
        
        RuleFor(x => x.Email)
            .NotEmpty().EmailAddress().WithMessage("Valid email is required");
        
        RuleFor(x => x.Password)
            .NotEmpty().WithMessage("Password is required")
            .MinimumLength(8).WithMessage("Password must be at least 8 characters")
            .Matches(@"[A-Z]").WithMessage("Password must contain uppercase")
            .Matches(@"[a-z]").WithMessage("Password must contain lowercase")
            .Matches(@"[0-9]").WithMessage("Password must contain number");
    }
}

// 3. Handler
public class CreateUserCommandHandler(
    IUserRepository userRepository,
    IPasswordHashService passwordService,
    IStringLocalizer<SharedResources> localizer)
    : IRequestHandler<CreateUserCommand, Result<UserResult>>
{
    public async Task<Result<UserResult>> Handle(
        CreateUserCommand request,
        CancellationToken cancellationToken)
    {
        // Check if user exists
        var existingUser = await _userRepository.GetByEmailAsync(
            request.Email, 
            cancellationToken);
        
        if (existingUser != null)
            return Result<UserResult>.Failure(
                new Error(400, _localizer["UserAlreadyExists"]));
        
        // Create domain entity
        var passwordHash = _passwordService.Hash(request.Password);
        var newUser = User.Create(
            request.FirstName,
            request.LastName,
            Email.Create(request.Email),
            passwordHash);
        
        // Persist
        await _userRepository.CreateAsync(newUser, cancellationToken);
        
        // Return DTO
        var userDto = new UserResult
        {
            Id = newUser.Id,
            FirstName = newUser.FirstName,
            LastName = newUser.LastName,
            Email = newUser.Email.Value
        };
        
        return Result<UserResult>.Success(userDto);
    }
}

// 4. Controller
[ApiController]
[Route("api/v1/users")]
public class UsersController(IMediator mediator) : ControllerBase
{
    [HttpPost]
    public async Task<IActionResult> CreateUser(
        [FromBody] CreateUserCommand command,
        CancellationToken cancellationToken)
    {
        var result = await mediator.Send(command, cancellationToken);
        
        return result.IsSuccess
            ? CreatedAtAction(nameof(GetUser), new { id = result.Data.Id }, result)
            : BadRequest(result);
    }
}
```

#### CQRS Query Implementation

```csharp
// 1. Query Definition
public class GetUserByIdQuery : IRequest<Result<UserDetailResult>>
{
    public int UserId { get; set; }
}

// 2. Handler (Simple queries often don't need validators)
public class GetUserByIdQueryHandler(IUserRepository userRepository)
    : IRequestHandler<GetUserByIdQuery, Result<UserDetailResult>>
{
    public async Task<Result<UserDetailResult>> Handle(
        GetUserByIdQuery request,
        CancellationToken cancellationToken)
    {
        var user = await _userRepository.GetByIdAsync(
            request.UserId,
            cancellationToken);
        
        if (user == null)
            return Result<UserDetailResult>.Failure(
                new Error(404, "User not found"));
        
        var result = new UserDetailResult
        {
            Id = user.Id,
            FirstName = user.FirstName,
            LastName = user.LastName,
            Email = user.Email.Value,
            CreatedAt = user.CreatedAt,
            UpdatedAt = user.UpdatedAt
        };
        
        return Result<UserDetailResult>.Success(result);
    }
}

// 3. Controller
[HttpGet("{id}")]
public async Task<IActionResult> GetUser(
    int id,
    CancellationToken cancellationToken)
{
    var query = new GetUserByIdQuery { UserId = id };
    var result = await mediator.Send(query, cancellationToken);
    
    return result.IsSuccess ? Ok(result) : NotFound(result);
}
```

#### Pipeline Behaviors

```csharp
// Validation Behavior - Runs for every request
public class ValidationBehavior<TRequest, TResponse>(
    IEnumerable<IValidator<TRequest>> validators)
    : IPipelineBehavior<TRequest, TResponse>
    where TRequest : IRequest<TResponse>
{
    public async Task<TResponse> Handle(
        TRequest request,
        RequestHandlerDelegate<TResponse> next,
        CancellationToken cancellationToken)
    {
        if (validators.Any())
        {
            var context = new ValidationContext<TRequest>(request);
            var validationResults = await Task.WhenAll(
                validators.Select(v => v.ValidateAsync(context, cancellationToken)));
            
            var failures = validationResults
                .SelectMany(r => r.Errors)
                .Where(f => f != null)
                .ToList();
            
            if (failures.Any())
                throw new ValidationException(failures);  // Caught by exception middleware
        }
        
        return await next();
    }
}

// Logging Behavior - Monitor handler execution
public class LoggingBehavior<TRequest, TResponse>(ILogger<LoggingBehavior<TRequest, TResponse>> logger)
    : IPipelineBehavior<TRequest, TResponse>
    where TRequest : IRequest<TResponse>
{
    public async Task<TResponse> Handle(
        TRequest request,
        RequestHandlerDelegate<TResponse> next,
        CancellationToken cancellationToken)
    {
        var requestName = typeof(TRequest).Name;
        
        logger.LogInformation("Executing request: {RequestName}", requestName);
        
        var sw = Stopwatch.StartNew();
        var response = await next();
        sw.Stop();
        
        logger.LogInformation(
            "Request {RequestName} completed in {ElapsedMilliseconds}ms",
            requestName,
            sw.ElapsedMilliseconds);
        
        return response;
    }
}

// Transaction Behavior - Wrap handlers in transactions
public class TransactionBehavior<TRequest, TResponse>(IUnitOfWork unitOfWork)
    : IPipelineBehavior<TRequest, TResponse>
    where TRequest : IRequest<TResponse>
{
    public async Task<TResponse> Handle(
        TRequest request,
        RequestHandlerDelegate<TResponse> next,
        CancellationToken cancellationToken)
    {
        using var transaction = await _unitOfWork.BeginTransactionAsync(cancellationToken);
        try
        {
            var response = await next();
            await transaction.CommitAsync(cancellationToken);
            return response;
        }
        catch
        {
            await transaction.RollbackAsync(cancellationToken);
            throw;
        }
    }
}
```

#### Service Registration

```csharp
public static class ApplicationServiceRegistration
{
    public static IServiceCollection AddApplicationLayer(
        this IServiceCollection services)
    {
        // MediatR - CQRS Framework
        services.AddMediatR(config =>
        {
            config.RegisterServicesFromAssembly(AssemblyReference.Assembly);
            
            // Register behaviors (order matters - top to bottom)
            config.AddOpenBehavior(typeof(ValidationBehavior<,>));
            config.AddOpenBehavior(typeof(LoggingBehavior<,>));
            config.AddOpenBehavior(typeof(TransactionBehavior<,>));
        });
        
        // Validation - FluentValidation
        services.AddValidatorsFromAssembly(AssemblyReference.Assembly);
        
        // Mapping - AutoMapper
        services.AddAutoMapper(config =>
        {
            config.AddMaps(AssemblyReference.Assembly);
            config.AllowNullDestinationValues = false;
        });
        
        return services;
    }
}
```

---

### Project 3: Infrastructure Layer (e.g., `CompanyName.Infrastructure`)

**Purpose**: External system integration, data persistence, framework implementation.

**Dependency**: Application + Domain

#### Folder Structure

```
CompanyName.Infrastructure/
??? Data/
?   ??? Context/
?   ?   ??? ApplicationDbContext.cs      # EF Core DbContext
?   ??? Configurations/
?       ??? UserConfiguration.cs         # Entity mappings
?       ??? OrderConfiguration.cs
?       ??? ... (one per entity)
??? Repositories/
?   ??? BaseRepository.cs                # Generic CRUD
?   ??? UserRepository.cs                # User-specific logic
?   ??? OrderRepository.cs
?   ??? ... (one per aggregate)
??? Services/
?   ??? EmailService.cs
?   ??? FileStorageService.cs
?   ??? AuthenticationService.cs
?   ??? CacheService.cs
?   ??? ... (external integrations)
??? Identity/
?   ??? CurrentUserService.cs
?   ??? TokenService.cs
?   ??? PasswordHashService.cs
??? Logging/
?   ??? LoggerAdapter.cs
?   ??? ... (logging implementations)
??? External/
?   ??? PaymentGatewayClient.cs
?   ??? ThirdPartyApiClient.cs
?   ??? ... (external API clients)
??? InfrastructureServiceRegistration.cs
??? GlobalUsing.Infrastructure.cs
```

#### Repository Implementation

```csharp
// Base Repository - Generic CRUD operations
public class BaseRepository<T>(ApplicationDbContext context) : IBaseRepository<T>
    where T : class
{
    protected readonly ApplicationDbContext _context = context;
    
    public virtual async Task<T?> GetByIdAsync(int id, CancellationToken cancellationToken = default)
        => await _context.Set<T>().FindAsync(new object[] { id }, cancellationToken);
    
    public virtual async Task<List<T>> GetAllAsync(CancellationToken cancellationToken = default)
        => await _context.Set<T>()
            .AsNoTracking()
            .ToListAsync(cancellationToken);
    
    public virtual async Task<T> CreateAsync(T entity, CancellationToken cancellationToken = default)
    {
        await _context.Set<T>().AddAsync(entity, cancellationToken);
        await _context.SaveChangesAsync(cancellationToken);
        return entity;
    }
    
    public virtual async Task<T> UpdateAsync(T entity, CancellationToken cancellationToken = default)
    {
        _context.Set<T>().Update(entity);
        await _context.SaveChangesAsync(cancellationToken);
        return entity;
    }
    
    public virtual async Task<bool> DeleteAsync(int id, CancellationToken cancellationToken = default)
    {
        var entity = await GetByIdAsync(id, cancellationToken);
        if (entity == null) return false;
        
        _context.Set<T>().Remove(entity);
        await _context.SaveChangesAsync(cancellationToken);
        return true;
    }
}

// Specialized Repository - Business-specific logic
public class UserRepository(ApplicationDbContext context)
    : BaseRepository<User>(context), IUserRepository
{
    public async Task<User?> GetByEmailAsync(string email, CancellationToken cancellationToken = default)
        => await _context.Users
            .AsNoTracking()
            .FirstOrDefaultAsync(u => u.Email.Value == email, cancellationToken);
    
    public async Task<List<User>> GetAdministratorsAsync(CancellationToken cancellationToken = default)
        => await _context.Users
            .AsNoTracking()
            .Where(u => u.Role == UserRole.Administrator)
            .ToListAsync(cancellationToken);
    
    public async Task<PagedResult<User>> GetPagedAsync(
        int pageNumber,
        int pageSize,
        CancellationToken cancellationToken = default)
    {
        var total = await _context.Users.CountAsync(cancellationToken);
        
        var items = await _context.Users
            .AsNoTracking()
            .Skip((pageNumber - 1) * pageSize)
            .Take(pageSize)
            .ToListAsync(cancellationToken);
        
        return new PagedResult<User>(items, total, pageNumber, pageSize);
    }
}
```

#### Entity Configuration (Fluent API)

```csharp
// Entity configuration - Separates ORM mapping from domain entities
public class UserConfiguration : IEntityTypeConfiguration<User>
{
    public void Configure(EntityTypeBuilder<User> builder)
    {
        builder.HasKey(u => u.Id);
        
        builder.ToTable("Users");
        
        builder.Property(u => u.FirstName)
            .HasMaxLength(100)
            .IsRequired();
        
        builder.Property(u => u.LastName)
            .HasMaxLength(100)
            .IsRequired();
        
        // Value Object mapping
        builder.Property(u => u.Email)
            .HasConversion(
                v => v.Value,
                v => Email.Create(v))
            .HasMaxLength(255)
            .IsRequired();
        
        builder.Property(u => u.PasswordHash)
            .HasMaxLength(500)
            .IsRequired();
        
        builder.Property(u => u.Role)
            .HasConversion<string>();
        
        builder.Property(u => u.CreatedAt)
            .HasDefaultValueSql("GETUTCDATE()");
        
        // Relationships
        builder.HasMany(u => u.Orders)
            .WithOne(o => o.User)
            .HasForeignKey(o => o.UserId)
            .OnDelete(DeleteBehavior.Cascade);
        
        // Indexes for performance
        builder.HasIndex(u => u.Email)
            .IsUnique();
        
        // Seed initial data if needed
        builder.HasData(
            new User { Id = 1, FirstName = "Admin", LastName = "User", /* ... */ }
        );
    }
}
```

#### External Service Integration

```csharp
// Email Service - External dependency
public interface IEmailService
{
    Task<Result> SendEmailAsync(string to, string subject, string body, CancellationToken cancellationToken);
}

public class EmailService(
    IConfiguration configuration,
    ILogger<EmailService> logger) : IEmailService
{
    private readonly string _smtpHost = configuration["Email:SmtpHost"];
    private readonly int _smtpPort = int.Parse(configuration["Email:SmtpPort"] ?? "587");
    
    public async Task<Result> SendEmailAsync(
        string to,
        string subject,
        string body,
        CancellationToken cancellationToken)
    {
        try
        {
            using var client = new SmtpClient(_smtpHost, _smtpPort);
            client.EnableSsl = true;
            
            // Configure credentials from configuration
            var message = new MailMessage("noreply@company.com", to, subject, body);
            
            await client.SendMailAsync(message, cancellationToken);
            
            logger.LogInformation("Email sent to {To}", to);
            return Result.Success();
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Failed to send email to {To}", to);
            return Result.Failure(new Error(500, "Failed to send email"));
        }
    }
}
```

#### Service Registration

```csharp
public static class InfrastructureServiceRegistration
{
    public static IServiceCollection AddInfrastructureLayer(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        // Database
        services.AddDbContext<ApplicationDbContext>(options =>
            options.UseSqlServer(configuration.GetConnectionString("DefaultConnection")));
        
        // Repositories
        services.AddScoped(typeof(IBaseRepository<>), typeof(BaseRepository<>));
        services.AddScoped<IUserRepository, UserRepository>();
        services.AddScoped<IOrderRepository, OrderRepository>();
        
        // Services
        services.AddScoped<IEmailService, EmailService>();
        services.AddScoped<IFileStorageService, FileStorageService>();
        services.AddScoped<IPasswordHashService, PasswordHashService>();
        services.AddScoped<ITokenService, JwtTokenService>();
        services.AddScoped<ICacheService, RedisCacheService>();
        
        // Identity
        services.AddScoped<ICurrentUserService, CurrentUserService>();
        
        // Configuration
        services.Configure<JwtSettings>(configuration.GetSection(nameof(JwtSettings)));
        services.Configure<CacheSettings>(configuration.GetSection(nameof(CacheSettings)));
        
        return services;
    }
}
```

---

### Project 4: API Layer (e.g., `CompanyName.Api`)

**Purpose**: HTTP endpoint definitions, request handling, presentation concerns.

**Dependency**: All layers (orchestration point)

#### Folder Structure

```
CompanyName.Api/
??? Controllers/
?   ??? BaseController.cs                # Base class with common methods
?   ??? V1/
?       ??? UsersController.cs
?       ??? OrdersController.cs
?       ??? ... (endpoint controllers)
??? Middlewares/
?   ??? ExceptionHandlingMiddleware.cs   # Global exception handling
?   ??? AuthenticationMiddleware.cs      # JWT validation
?   ??? CorrelationIdMiddleware.cs       # Request tracking
?   ??? ... (cross-cutting middlewares)
??? Helpers/
?   ??? ServiceRegistration.cs           # API DI configuration
?   ??? SwaggerOptions.cs                # Swagger configuration
?   ??? CurrentUserService.cs            # ICurrentUserService impl
?   ??? ... (API-specific utilities)
??? Filters/
?   ??? ExceptionFilter.cs               # MVC-level exception handling
?   ??? ValidationFilter.cs              # Model validation
??? Program.cs                            # Entry point & startup
??? appsettings.json
```

#### Base Controller Pattern

```csharp
// Shared controller functionality
[ApiController]
[Route("api/v{version:apiVersion}/[controller]")]
[ApiVersion("1.0")]
public abstract class BaseController(IMediator mediator) : ControllerBase
{
    protected readonly IMediator Mediator = mediator;
    
    /// <summary>
    /// Sends a request through MediatR pipeline and maps result to HTTP response.
    /// </summary>
    protected async Task<IActionResult> Send<T>(
        IRequest<Result<T>> request,
        CancellationToken cancellationToken = default)
    {
        var result = await Mediator.Send(request, cancellationToken);
        
        return result.IsSuccess
            ? Ok(result)
            : result.Error?.Code switch
            {
                400 => BadRequest(result),
                401 => Unauthorized(result),
                403 => Forbid(),
                404 => NotFound(result),
                409 => Conflict(result),
                _ => StatusCode(500, result)
            };
    }
}

// Concrete controller
[Route("api/v{version:apiVersion}/users")]
public class UsersController(IMediator mediator) : BaseController(mediator)
{
    /// <summary>
    /// Create a new user.
    /// </summary>
    /// <remarks>
    /// POST /api/v1.0/users
    /// 
    /// Request body:
    /// {
    ///     "firstName": "John",
    ///     "lastName": "Doe",
    ///     "email": "john@example.com",
    ///     "password": "SecurePass123!"
    /// }
    /// </remarks>
    [HttpPost]
    [ProducesResponseType(typeof(Result<UserResult>), 201)]
    [ProducesResponseType(typeof(Result), 400)]
    public async Task<IActionResult> CreateUser(
        [FromBody] CreateUserCommand command,
        CancellationToken cancellationToken)
    {
        var result = await Send(command, cancellationToken);
        
        return result.IsSuccess
            ? CreatedAtAction(nameof(GetUser), new { id = result.Data?.Id }, result)
            : result;
    }
    
    /// <summary>
    /// Get a user by ID.
    /// </summary>
    [HttpGet("{id}")]
    [ProducesResponseType(typeof(Result<UserDetailResult>), 200)]
    [ProducesResponseType(typeof(Result), 404)]
    public async Task<IActionResult> GetUser(
        int id,
        CancellationToken cancellationToken)
    {
        var query = new GetUserByIdQuery { UserId = id };
        return await Send(query, cancellationToken);
    }
}
```

#### Middleware Pipeline

```csharp
// Program.cs - Middleware configuration
var app = builder.Build();

// HTTPS redirection
if (!app.Environment.IsDevelopment())
    app.UseHttpsRedirection();

// Swagger documentation
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI(options =>
    {
        var descriptions = app.DescribeApiVersions();
        foreach (var description in descriptions)
        {
            options.SwaggerEndpoint(
                $"/swagger/{description.GroupName}/swagger.json",
                description.GroupName);
        }
    });
}

// CORS
app.UseCors("CorsPolicy");

// Request correlation
app.UseMiddleware<CorrelationIdMiddleware>();

// Exception handling (catch all)
app.UseMiddleware<ExceptionHandlingMiddleware>();

// Authentication & Authorization
app.UseAuthentication();
app.UseAuthorization();

// Routing
app.MapControllers();

app.Run();
```

#### Exception Handling Middleware

```csharp
public class ExceptionHandlingMiddleware(
    RequestDelegate next,
    ILogger<ExceptionHandlingMiddleware> logger)
{
    public async Task InvokeAsync(HttpContext context)
    {
        try
        {
            await next(context);
        }
        catch (ValidationException ex)
        {
            logger.LogWarning("Validation failed: {Errors}", ex.Errors);
            
            var errors = ex.Errors
                .Select(e => new ValidationError(e.PropertyName, e.ErrorMessage))
                .ToList();
            
            var response = Result<ResultEmpty>.ValidationError(errors);
            
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            context.Response.ContentType = "application/json";
            
            await context.Response.WriteAsJsonAsync(response);
        }
        catch (UnauthorizedException ex)
        {
            logger.LogWarning("Unauthorized access: {Message}", ex.Message);
            
            var response = Result<ResultEmpty>.Failure(
                new Error(401, ex.Message));
            
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            await context.Response.WriteAsJsonAsync(response);
        }
        catch (NotFoundException ex)
        {
            logger.LogWarning("Resource not found: {Message}", ex.Message);
            
            var response = Result<ResultEmpty>.Failure(
                new Error(404, ex.Message));
            
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            await context.Response.WriteAsJsonAsync(response);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Unhandled exception occurred");
            
            var response = Result<ResultEmpty>.Failure(
                new Error(500, "An unexpected error occurred"));
            
            context.Response.StatusCode = StatusCodes.Status500InternalServerError;
            context.Response.ContentType = "application/json";
            
            await context.Response.WriteAsJsonAsync(response);
        }
    }
}
```

#### Service Registration

```csharp
public static class ApiServiceRegistration
{
    public static IServiceCollection AddApiServices(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        // Controllers
        services.AddControllers();
        
        // API Versioning
        services.AddApiVersioning(options =>
        {
            options.DefaultApiVersion = new ApiVersion(1, 0);
            options.AssumeDefaultVersionWhenUnspecified = true;
            options.ReportApiVersions = true;
        })
        .AddApiExplorer(options =>
        {
            options.GroupNameFormat = "'v'VVV";
            options.SubstituteApiVersionInUrl = true;
        });
        
        // Swagger/OpenAPI
        services.AddSwaggerGen(options =>
        {
            var jwtSecurityScheme = new OpenApiSecurityScheme
            {
                Name = "Authorization",
                In = ParameterLocation.Header,
                Type = SecuritySchemeType.Http,
                Scheme = "bearer",
                BearerFormat = "JWT",
                Reference = new OpenApiReference
                {
                    Id = JwtBearerDefaults.AuthenticationScheme,
                    Type = ReferenceType.SecurityScheme
                }
            };
            
            options.AddSecurityDefinition("Bearer", jwtSecurityScheme);
            options.AddSecurityRequirement(new OpenApiSecurityRequirement
            {
                { jwtSecurityScheme, Array.Empty<string>() }
            });
            
            // XML comments
            var xmlFile = $"{Assembly.GetExecutingAssembly().GetName().Name}.xml";
            var xmlPath = Path.Combine(AppContext.BaseDirectory, xmlFile);
            options.IncludeXmlComments(xmlPath);
        });
        
        // Authentication
        services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
            .AddJwtBearer(options =>
            {
                var jwtSettings = configuration.GetSection(nameof(JwtSettings))
                    .Get<JwtSettings>();
                
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(
                        Encoding.UTF8.GetBytes(jwtSettings.Key)),
                    ValidateIssuer = false,
                    ValidateAudience = false,
                    ValidateLifetime = true,
                    ClockSkew = TimeSpan.Zero
                };
            });
        
        // CORS
        services.AddCors(options =>
        {
            options.AddPolicy("CorsPolicy", policy =>
            {
                var allowedOrigins = configuration
                    .GetSection("AllowedOrigins")
                    .Get<string[]>() ?? Array.Empty<string>();
                
                policy
                    .WithOrigins(allowedOrigins)
                    .AllowAnyHeader()
                    .AllowAnyMethod()
                    .AllowCredentials();
            });
        });
        
        // Logging
        services.AddLogging(config =>
        {
            config.AddConsole();
            config.AddDebug();
        });
        
        // HTTP Context Accessor
        services.AddHttpContextAccessor();
        
        return services;
    }
}
```

---

### Project 5: Resources Layer (e.g., `CompanyName.Resources`)

**Purpose**: Localization, static strings, configuration templates.

**Dependency**: Domain (shared) or none

#### Structure

```
CompanyName.Resources/
??? Localization/
?   ??? SharedResources.Designer.cs      # Generated from .resx
?   ??? SharedResources.resx             # English strings
?   ??? SharedResources.es.resx          # Spanish strings
??? Constants/
?   ??? SharedConstants.cs
??? GlobalUsing.Resources.cs
```

#### Usage

```csharp
// In handlers, services, etc.
public class CreateUserCommandHandler(
    IStringLocalizer<SharedResources> localizer)
    : IRequestHandler<CreateUserCommand, Result<UserResult>>
{
    public async Task<Result<UserResult>> Handle(
        CreateUserCommand request,
        CancellationToken cancellationToken)
    {
        // Localized error message - returns translated string based on culture
        return Result<UserResult>.Failure(
            new Error(400, localizer["UserAlreadyExists"]));
    }
}
```

---

## CQRS Pattern Implementation

### Command vs Query: Key Differences

| Aspect | Command | Query |
|--------|---------|-------|
| **Purpose** | Create, Update, Delete | Read, Retrieve, Report |
| **Data Mutation** | ? Modifies state | ? No side effects |
| **Caching** | Invalidate cache | Cache-friendly |
| **Performance** | Slower (writes) | Faster (reads) |
| **Scalability** | Scale writes separately | Scale reads separately |
| **Idempotency** | Should be (for retries) | Always idempotent |
| **Error Handling** | Business exceptions | Not found scenarios |
| **Database** | Write operations | Read-optimized models |

### Command Flow

```
????????????????????
?  Client Request  ?
????????????????????
         ?
    POST /api/v1/users
    Body: { firstName, email, ... }
         ?
    ?????????????????????????
    ? Model Binding         ?
    ? Deserialize JSON      ?
    ????????????????????????
         ?
    ????????????????????????
    ? CreateUserCommand     ?
    ? { FirstName, Email }  ?
    ???????????????????????
         ?
    ?????????????????????????
    ? MediatR Pipeline      ?
    ?  ?? Validation        ?
    ?  ?? Transaction Start ?
    ?  ?? Execute Handler   ?
    ????????????????????????
         ?
    ??????????????????????????
    ? Handler Execution      ?
    ?  ?? Validate business  ?
    ?  ?? Create entity      ?
    ?  ?? Save to database   ?
    ?  ?? Return result      ?
    ?????????????????????????
         ?
    ?????????????????????????
    ? Transaction Commit    ?
    ? Invalidate Cache      ?
    ????????????????????????
         ?
    ????????????????????????????
    ? Result<UserResult>       ?
    ? { IsSuccess, Data, Error}?
    ???????????????????????????
         ?
    ?????????????????
    ? HTTP Response ?
    ? 201 Created   ?
    ?????????????????
```

### Query Flow

```
????????????????????
?  Client Request  ?
????????????????????
         ?
    GET /api/v1/users/5
         ?
    ?????????????????????????
    ? Route Binding         ?
    ? Extract parameter: 5  ?
    ????????????????????????
         ?
    ???????????????????????
    ? GetUserByIdQuery    ?
    ? { UserId: 5 }       ?
    ??????????????????????
         ?
    ?????????????????????????
    ? MediatR Pipeline      ?
    ?  ?? Execute Handler   ?
    ?     (No validation)   ?
    ????????????????????????
         ?
    ??????????????????????????
    ? Handler Execution      ?
    ?  ?? Check cache        ?
    ?  ?? Query database     ?
    ?  ?? Map to DTO         ?
    ?  ?? Cache result       ?
    ?????????????????????????
         ?
    ?????????????????????????????
    ? Result<UserDetailResult>  ?
    ? { IsSuccess, Data, Error} ?
    ????????????????????????????
         ?
    ?????????????????
    ? HTTP Response ?
    ? 200 OK        ?
    ?????????????????
```

### StoredRequests Pattern

Complex queries sometimes need intermediate storage:

```csharp
// For complex filtering, pagination, and sorting
public class UserSearchRequest : IRequest<Result<PagedResult<UserResult>>>
{
    public string? SearchTerm { get; set; }
    public UserRole? Role { get; set; }
    public DateTime? CreatedAfter { get; set; }
    public int PageNumber { get; set; } = 1;
    public int PageSize { get; set; } = 10;
    public string SortBy { get; set; } = "Id";
    public bool SortDescending { get; set; } = false;
}

public class UserSearchRequestHandler(IUserRepository repository)
    : IRequestHandler<UserSearchRequest, Result<PagedResult<UserResult>>>
{
    public async Task<Result<PagedResult<UserResult>>> Handle(
        UserSearchRequest request,
        CancellationToken cancellationToken)
    {
        var query = _repository.GetQueryable();
        
        // Apply filters
        if (!string.IsNullOrEmpty(request.SearchTerm))
            query = query.Where(u => u.FirstName.Contains(request.SearchTerm)
                || u.LastName.Contains(request.SearchTerm)
                || u.Email.Value.Contains(request.SearchTerm));
        
        if (request.Role.HasValue)
            query = query.Where(u => u.Role == request.Role);
        
        if (request.CreatedAfter.HasValue)
            query = query.Where(u => u.CreatedAt >= request.CreatedAfter);
        
        // Apply sorting
        query = request.SortDescending
            ? query.OrderByDescending(u => EF.Property<object>(u, request.SortBy))
            : query.OrderBy(u => EF.Property<object>(u, request.SortBy));
        
        // Get total count
        var total = await query.CountAsync(cancellationToken);
        
        // Apply pagination
        var items = await query
            .Skip((request.PageNumber - 1) * request.PageSize)
            .Take(request.PageSize)
            .ToListAsync(cancellationToken);
        
        var dtos = items.Select(u => new UserResult { /* ... */ });
        
        return Result<PagedResult<UserResult>>.Success(
            new PagedResult<UserResult>(dtos, total, request.PageNumber, request.PageSize));
    }
}
```

---

## Dependency Management & Injection

### Dependency Direction Rules

```
                ALLOWED DEPENDENCIES
????????????????????????????????????????????????????????

API Layer
?? Can depend on: Application, Infrastructure, Domain
?? Cannot depend on: (nothing)

Infrastructure Layer
?? Can depend on: Application, Domain
?? Cannot depend on: API

Application Layer
?? Can depend on: Domain
?? Cannot depend on: Infrastructure, API

Domain Layer
?? Can depend on: (nothing)
?? Cannot depend on: All other layers

Resources Layer
?? Can depend on: (shared - no dependencies)
?? Cannot depend on: All other layers

                DEPENDENCY GRAPH
                    API ??
                    ?    ?
            Infrastructure ? Application
                    ?    ?
                  Domain ??

Each layer only knows about layers BELOW it.
```

### Compiler Verification

```csharp
// ? COMPILE ERROR - Infrastructure references API
using SomeCompany.Api;  // ? Compiler error: namespace not found

// ? CORRECT - Only upward dependencies
namespace SomeCompany.Infrastructure
{
    using SomeCompany.Application;      // ? Allowed
    using SomeCompany.Domain;           // ? Allowed
    using SomeCompany.Infrastructure;   // ? Self reference
    
    // Never:
    // using SomeCompany.Api;            // ? Not allowed
}
```

### Dependency Injection Container Flow

```csharp
// Program.cs - Startup configuration
var builder = WebApplicationBuilder.CreateBuilder(args);

// Step 1: Register Domain Layer (rarely needed - mostly entities)
// (Usually no explicit registrations needed)

// Step 2: Register Application Layer
builder.Services.AddApplicationLayer();
// Registers: MediatR, Validators, AutoMapper, Behaviors

// Step 3: Register Infrastructure Layer
builder.Services.AddInfrastructureLayer(builder.Configuration);
// Registers: DbContext, Repositories, Services

// Step 4: Register API Layer
builder.Services.AddApiLayer(builder.Configuration);
// Registers: Controllers, Authentication, CORS, Logging

// Step 5: Build and run
var app = builder.Build();
app.Run();

// Runtime: When request comes in
// HttpContext.RequestServices (IServiceProvider) resolves dependencies:
// 1. Controller requests IMediator (registered in Application layer)
// 2. IMediator creates handler for request (discovered via reflection)
// 3. Handler constructor requests IRepository (registered in Infrastructure)
// 4. IRepository is created and injected
// 5. Handler requests DbContext (registered in Infrastructure)
// 6. DbContext is created (Scoped lifetime - same instance for request)
// 7. All dependencies resolved and injected
```

### GlobalUsings Pattern

```csharp
// GlobalUsing.Api.cs - Avoid repetitive using statements
global using System;
global using System.Collections.Generic;
global using System.Linq;
global using System.Threading.Tasks;
global using System.Threading;
global using Microsoft.AspNetCore.Mvc;
global using Microsoft.AspNetCore.Authorization;
global using SomeCompany.Application;
global using SomeCompany.Application.Features.Users.Commands;
global using SomeCompany.Application.Features.Users.Queries;
global using SomeCompany.Domain;

// Now in any .cs file in API project, these namespaces are already imported
// No need for explicit using statements
```

### Service Registration Checklist

```csharp
// ? DO:
services.AddScoped<IRepository, Repository>();        // Interface + Implementation
services.AddScoped<IUserService>(sp =>                 // Factory registration
{
    var logger = sp.GetRequiredService<ILogger>();
    return new UserService(logger);
});

// ? DON'T:
services.AddScoped(typeof(IRepository), typeof(Repository));  // Generic form (less readable)
services.AddScoped<Repository>();                            // No interface (tight coupling)
var repo = new Repository();                                  // Manual instantiation
services.AddScoped(_ => new Repository());                    // Factory without DI access
```

---

## Complete Request Lifecycle

### Step-by-Step Request Flow: GetUserById Query

```
??????????????????????????????????????????????????????????????????????????
? 1. HTTP REQUEST ARRIVES                                                 ?
?                                                                         ?
? GET /api/v1.0/users/42                                                ?
? Headers:                                                               ?
?   Authorization: Bearer eyJhbGc...                                     ?
?   Accept: application/json                                             ?
?   Accept-Language: en-US                                               ?
????????????????????????????????????????????????????????????????????????
                              ?
????????????????????????????????????????????????????????????????????????
? 2. MIDDLEWARE PIPELINE BEGINS                                         ?
?                                                                       ?
? a) CorrelationIdMiddleware                                            ?
?    Generate unique request ID for tracing                             ?
?    HttpContext.TraceIdentifier = Guid.NewGuid()                       ?
?                                                                       ?
? b) ExceptionHandlingMiddleware                                        ?
?    Wrap entire request in try-catch block                             ?
?    Any exception will be caught and formatted here                    ?
?                                                                       ?
? c) CorsMiddleware                                                     ?
?    Check if origin allowed in configuration                           ?
?    Add CORS headers to response if allowed                            ?
?                                                                       ?
? d) AuthenticationMiddleware                                           ?
?    Extract JWT from Authorization header                              ?
?    Validate token signature using configured key                      ?
?    Extract claims (user ID, roles, etc.)                              ?
?    Set HttpContext.User with claims principal                         ?
?    User now available in handlers                                     ?
?                                                                       ?
? e) AuthorizationMiddleware                                            ?
?    Check [Authorize] attributes on controller/action                  ?
?    For this GET request: no authorization required                    ?
?    (If [Authorize(Roles = "Admin")] was present, validation here)     ?
????????????????????????????????????????????????????????????????????????
                              ?
????????????????????????????????????????????????????????????????????????
? 3. ROUTING & CONTROLLER DISCOVERY                                     ?
?                                                                       ?
? Route template: api/v{version:apiVersion}/[controller]               ?
? Matched route: api/v1.0/users                                        ?
?                                                                       ?
? Controller: UsersController (inherits BaseController)                ?
? Action: GetUser(int id)                                              ?
? HTTP Method: GET                                                     ?
? Route parameter: id = 42                                             ?
????????????????????????????????????????????????????????????????????????
                              ?
????????????????????????????????????????????????????????????????????????
? 4. MODEL BINDING                                                       ?
?                                                                       ?
? Parameter: int id = 42 (from route)                                  ?
? Model state validation: ? Valid (primitive type, no validators)      ?
? Dependencies injected into controller:                                ?
?   UsersController(IMediator mediator)                                ?
?   ? mediator = resolved from DI container                            ?
????????????????????????????????????????????????????????????????????????
                              ?
????????????????????????????????????????????????????????????????????????
? 5. ACTION EXECUTION - GetUser                                         ?
?                                                                       ?
? public async Task<IActionResult> GetUser(int id)                     ?
? {                                                                     ?
?     var query = new GetUserByIdQuery { UserId = id };                ?
?                                                                       ?
?     var result = await mediator.Send(query);                         ?
?                                                                       ?
?     return result.IsSuccess ? Ok(result) : NotFound(result);         ?
? }                                                                     ?
?                                                                       ?
? Action creates query object:                                          ?
?   GetUserByIdQuery { UserId: 42 }                                    ?
????????????????????????????????????????????????????????????????????????
                              ?
????????????????????????????????????????????????????????????????????????
? 6. MEDIATR PIPELINE EXECUTION                                         ?
?                                                                       ?
? mediator.Send(GetUserByIdQuery) triggers:                            ?
?                                                                       ?
? a) Behavior Pipeline (registered order):                              ?
?    ????????????????????????????????????????????                      ?
?    ? RequestHandlerDelegate<Result<T>>        ?                      ?
?    ?                                          ?                      ?
?    ? ?? ValidationBehavior<TRequest, TResponse>
?    ? ?  Check: No validators registered for GetUserByIdQuery       ?
?    ? ?  Result: Skip validation, continue                           ?
?    ? ?                                                              ?
?    ? ?? LoggingBehavior<TRequest, TResponse>                       ?
?    ? ?  Log: "Executing query: GetUserByIdQuery"                   ?
?    ? ?  Start stopwatch                                             ?
?    ? ?                                                              ?
?    ? ?? Execute Handler:                                            ?
?    ?    IRequestHandler<GetUserByIdQuery, Result<UserDetailResult>> ?
?    ?    GetUserByIdQueryHandler                                    ?
?    ?                                                              ?
?    ????????????????????????????????????????????                      ?
?                                                                       ?
? b) Handler Resolution (via reflection):                              ?
?    MediatR finds: GetUserByIdQueryHandler                           ?
?    Implements: IRequestHandler<GetUserByIdQuery, Result<...>>      ?
?    Dependencies:                                                     ?
?      - IUserRepository repository (constructor injected)            ?
?      - Repository resolved from DI as UserRepository instance       ?
?      - UserRepository depends on ApplicationDbContext               ?
?      - DbContext resolved (Scoped - new for this request)           ?
????????????????????????????????????????????????????????????????????????
                              ?
????????????????????????????????????????????????????????????????????????
? 7. HANDLER EXECUTION - GetUserByIdQueryHandler                       ?
?                                                                       ?
? public async Task<Result<UserDetailResult>> Handle(                  ?
?     GetUserByIdQuery request,                                        ?
?     CancellationToken cancellationToken)                             ?
? {                                                                     ?
?     var user = await _repository.GetByIdAsync(                       ?
?         request.UserId,                                              ?
?         cancellationToken);                                          ?
?                                                                       ?
?     if (user == null)                                                ?
?         return Result<UserDetailResult>.Failure(                     ?
?             new Error(404, "User not found"));                       ?
?                                                                       ?
?     var result = new UserDetailResult                                ?
?     {                                                                ?
?         Id = user.Id,                                               ?
?         FirstName = user.FirstName,                                  ?
?         Email = user.Email.Value,                                    ?
?         CreatedAt = user.CreatedAt                                   ?
?     };                                                               ?
?                                                                       ?
?     return Result<UserDetailResult>.Success(result);                 ?
? }                                                                     ?
?                                                                       ?
? Handler Flow:                                                        ?
? a) Repository.GetByIdAsync(42) called                               ?
? b) EF Core query executed against database                           ?
? c) User entity returned (or null if not found)                       ?
? d) If null: return error result (404)                                ?
? e) If exists: map to DTO and return success                          ?
????????????????????????????????????????????????????????????????????????
                              ?
????????????????????????????????????????????????????????????????????????
? 8. REPOSITORY LAYER - DATA ACCESS                                     ?
?                                                                       ?
? UserRepository.GetByIdAsync(42)                                      ?
? ?                                                                     ?
? ApplicationDbContext.Users                                            ?
?     .AsNoTracking()        // Read-only, no tracking overhead        ?
?     .FirstOrDefaultAsync(u => u.Id == 42)                           ?
? ?                                                                     ?
? EF Core Translation to SQL:                                          ?
? SELECT * FROM Users WHERE Id = 42                                   ?
? ?                                                                     ?
? Database Execution:                                                  ?
? ?? Check query cache                                                 ?
? ?? Parse SQL                                                         ?
? ?? Execute query plan                                                ?
? ?? Fetch result from data pages                                      ?
? ?? Return to application                                             ?
????????????????????????????????????????????????????????????????????????
                              ?
????????????????????????????????????????????????????????????????????????
? 9. RESULT MAPPING & RESPONSE CREATION                                 ?
?                                                                       ?
? Handler returns: Result<UserDetailResult>                            ?
? {                                                                     ?
?     IsSuccess: true,                                                 ?
?     Data: {                                                          ?
?         Id: 42,                                                      ?
?         FirstName: "John",                                           ?
?         Email: "john@example.com",                                   ?
?         CreatedAt: "2024-01-15T10:30:00Z"                            ?
?     },                                                               ?
?     Error: null,                                                     ?
?     ValidationErrors: null                                           ?
? }                                                                     ?
?                                                                       ?
? LoggingBehavior logs:                                                ?
? "Query GetUserByIdQuery completed in 125ms"                          ?
????????????????????????????????????????????????????????????????????????
                              ?
????????????????????????????????????????????????????????????????????????
? 10. ACTION RESULT MAPPING                                             ?
?                                                                       ?
? In BaseController.GetUser():                                         ?
?                                                                       ?
? if (result.IsSuccess)                                                ?
?     return Ok(result);  // ? OkObjectResult (HTTP 200)              ?
?                                                                       ?
? OkObjectResult encodes Result<UserDetailResult> to JSON              ?
????????????????????????????????????????????????????????????????????????
                              ?
????????????????????????????????????????????????????????????????????????
? 11. HTTP RESPONSE GENERATION                                          ?
?                                                                       ?
? Status Code: 200 OK                                                  ?
? Content-Type: application/json; charset=utf-8                        ?
? Content-Length: 425                                                  ?
? X-Correlation-ID: 3fa85f64-5717-4562-b3fc...                       ?
?                                                                       ?
? Body (JSON):                                                         ?
? {                                                                     ?
?     "isSuccess": true,                                               ?
?     "data": {                                                        ?
?         "id": 42,                                                    ?
?         "firstName": "John",                                         ?
?         "email": "john@example.com",                                 ?
?         "createdAt": "2024-01-15T10:30:00Z"                          ?
?     },                                                               ?
?     "error": null,                                                   ?
?     "validationErrors": null                                         ?
? }                                                                     ?
?                                                                       ?
? ASP.NET Core serializes Result<T> to JSON (camelCase by default)     ?
? Response sent to client                                              ?
????????????????????????????????????????????????????????????????????????
                              ?
????????????????????????????????????????????????????????????????????????
? 12. CLIENT RECEIVES RESPONSE                                          ?
?                                                                       ?
? HTTP/1.1 200 OK                                                       ?
? Content-Type: application/json                                        ?
?                                                                       ?
? {                                                                     ?
?     "isSuccess": true,                                               ?
?     "data": { "id": 42, ... }                                        ?
? }                                                                     ?
?                                                                       ?
? Client application parses JSON and displays user details              ?
??????????????????????????????????????????????????????????????????????
```

### Timeline Analysis

```
Total Time: ~50-150ms (typical for simple query)

Breakdown:
?? Network latency (client ? server):  20ms
?? Middleware pipeline:                 5ms
?  ?? Exception handling setup
?  ?? CORS evaluation
?  ?? Authentication/JWT validation
?  ?? Authorization check
?? Routing & model binding:             2ms
?? Action execution:                    3ms
?? MediatR behaviors:                   5ms
?? Handler execution:                   5ms
?? Database query:                      80ms  ? Most time spent here
?  ?? Query translation (LINQ ? SQL)
?  ?? Network to SQL Server
?  ?? Query execution
?  ?? Result deserialization
?? Result mapping:                      5ms
?? JSON serialization:                  5ms
?? Network latency (server ? client):  20ms
?? TOTAL:                             ~150ms

With caching (Cache hit):
?? Network latency (client ? server):  20ms
?? Middleware pipeline:                 5ms
?? MediatR pipeline:                    5ms
?? Handler (check cache):              10ms  ? Cache hit, no DB query
?? Result mapping:                      3ms
?? JSON serialization:                  3ms
?? Network latency (server ? client):  20ms
?? TOTAL:                              ~66ms  ? 55% faster with caching
```

---

## Cross-Cutting Concerns

### 1. **Logging & Observability**

```csharp
// Structural logging with context
public class LoggingBehavior<TRequest, TResponse>(
    ILogger<LoggingBehavior<TRequest, TResponse>> logger)
    : IPipelineBehavior<TRequest, TResponse>
{
    public async Task<TResponse> Handle(
        TRequest request,
        RequestHandlerDelegate<TResponse> next,
        CancellationToken cancellationToken)
    {
        var requestName = typeof(TRequest).Name;
        
        using (logger.BeginScope(new Dictionary<string, object>
        {
            { "RequestName", requestName },
            { "RequestId", Guid.NewGuid() },
            { "Timestamp", DateTime.UtcNow }
        }))
        {
            logger.LogInformation(
                "Starting request {RequestName}",
                requestName);
            
            try
            {
                var sw = Stopwatch.StartNew();
                var response = await next();
                sw.Stop();
                
                logger.LogInformation(
                    "Request {RequestName} completed in {ElapsedMilliseconds}ms",
                    requestName,
                    sw.ElapsedMilliseconds);
                
                return response;
            }
            catch (Exception ex)
            {
                logger.LogError(
                    ex,
                    "Request {RequestName} failed with exception",
                    requestName);
                throw;
            }
        }
    }
}
```

### 2. **Validation Strategy**

```
Validation Layers (In Order):
????????????????????????????????
? 1. Data Annotations          ? (fast fail on model binding)
?    [Required]                 ?
?    [EmailAddress]             ?
?    [StringLength]             ?
????????????????????????????????
                ?
????????????????????????????????
? 2. FluentValidation          ? (business rules)
?    RuleFor(x => x.Email)      ?
?        .EmailAddress()         ?
?        .Must(CheckUnique)      ?
????????????????????????????????
                ?
????????????????????????????????
? 3. Domain Validation         ? (in entity constructors)
?    if (email == null)         ?
?        throw new Exception(); ?
????????????????????????????????
                ?
????????????????????????????????
? 4. Business Logic            ? (in handlers)
?    if (user exists)           ?
?        return error;          ?
????????????????????????????????
```

### 3. **Exception Handling**

```csharp
// Custom exception hierarchy
public class ApplicationException : Exception
{
    public int ErrorCode { get; set; }
}

public class NotFoundException : ApplicationException
{
    public NotFoundException(string message)
        : base(message)
    {
        ErrorCode = 404;
    }
}

public class UnauthorizedException : ApplicationException
{
    public UnauthorizedException(string message)
        : base(message)
    {
        ErrorCode = 401;
    }
}

public class ValidationException : ApplicationException
{
    public ValidationException(IEnumerable<ValidationFailure> failures)
        : base("Validation failed")
    {
        ErrorCode = 400;
        Failures = failures.ToList();
    }
    
    public List<ValidationFailure> Failures { get; }
}

// In exception middleware
public class ExceptionHandlingMiddleware(
    RequestDelegate next,
    ILogger<ExceptionHandlingMiddleware> logger)
{
    public async Task InvokeAsync(HttpContext context)
    {
        try
        {
            await next(context);
        }
        catch (NotFoundException ex)
        {
            context.Response.StatusCode = 404;
            await context.Response.WriteAsJsonAsync(
                Result<ResultEmpty>.Failure(new Error(404, ex.Message)));
        }
        catch (UnauthorizedException ex)
        {
            context.Response.StatusCode = 401;
            await context.Response.WriteAsJsonAsync(
                Result<ResultEmpty>.Failure(new Error(401, ex.Message)));
        }
        catch (ValidationException ex)
        {
            context.Response.StatusCode = 400;
            var errors = ex.Failures
                .Select(f => new ValidationError(f.PropertyName, f.ErrorMessage))
                .ToList();
            await context.Response.WriteAsJsonAsync(
                Result<ResultEmpty>.ValidationError(errors));
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Unhandled exception");
            context.Response.StatusCode = 500;
            await context.Response.WriteAsJsonAsync(
                Result<ResultEmpty>.Failure(
                    new Error(500, "An unexpected error occurred")));
        }
    }
}
```

### 4. **Transaction Management**

```csharp
// Explicit transaction behavior
public class TransactionBehavior<TRequest, TResponse>(
    IUnitOfWork unitOfWork)
    : IPipelineBehavior<TRequest, TResponse>
    where TRequest : IRequest<TResponse>
{
    public async Task<TResponse> Handle(
        TRequest request,
        RequestHandlerDelegate<TResponse> next,
        CancellationToken cancellationToken)
    {
        using var transaction = await unitOfWork.BeginTransactionAsync(cancellationToken);
        try
        {
            var response = await next();
            await transaction.CommitAsync(cancellationToken);
            return response;
        }
        catch (Exception)
        {
            await transaction.RollbackAsync(cancellationToken);
            throw;
        }
    }
}

// Or: Auto-transaction for command handlers
public class CommandTransactionBehavior<TRequest, TResponse>(
    ApplicationDbContext dbContext)
    : IPipelineBehavior<TRequest, TResponse>
    where TRequest : IRequest<TResponse>
{
    // Only apply to commands, not queries
    public async Task<TResponse> Handle(
        TRequest request,
        RequestHandlerDelegate<TResponse> next,
        CancellationToken cancellationToken)
    {
        // Check if this is a command (contains "Command" in name)
        if (!typeof(TRequest).Name.EndsWith("Command"))
            return await next();
        
        using var transaction = await dbContext.Database
            .BeginTransactionAsync(cancellationToken);
        try
        {
            var response = await next();
            await transaction.CommitAsync(cancellationToken);
            return response;
        }
        catch
        {
            await transaction.RollbackAsync(cancellationToken);
            throw;
        }
    }
}
```

### 5. **Security Concerns**

```csharp
// JWT Authentication
services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(keyBytes),
            ValidateIssuer = false,
            ValidateAudience = false,
            ValidateLifetime = true,
            ClockSkew = TimeSpan.Zero  // No time skew for strict validation
        };
    });

// Authorization on handlers
[Authorize]  // Requires authentication
public class UpdateUserCommand : IRequest<Result<UserResult>>
{
    public int UserId { get; set; }
    public string NewEmail { get; set; }
}

[Authorize(Roles = "Admin")]  // Requires specific role
public class DeleteUserCommand : IRequest<Result>
{
    public int UserId { get; set; }
}

// In handler: Check current user permissions
public class UpdateUserCommandHandler(
    ICurrentUserService currentUserService,
    IUserRepository userRepository)
{
    public async Task<Result<UserResult>> Handle(
        UpdateUserCommand request,
        CancellationToken cancellationToken)
    {
        var currentUser = _currentUserService.GetCurrentUser();
        
        // Ensure user can only update their own profile (unless admin)
        if (request.UserId != currentUser.Id && currentUser.Role != UserRole.Admin)
            return Result<UserResult>.Failure(
                new Error(403, "Forbidden"));
        
        // ... rest of handler
    }
}
```

---

## Testing & Testability

### Unit Testing Handlers

```csharp
[TestFixture]
public class CreateUserCommandHandlerTests
{
    private Mock<IUserRepository> _mockUserRepository;
    private Mock<IPasswordHashService> _mockPasswordService;
    private Mock<IStringLocalizer<SharedResources>> _mockLocalizer;
    private CreateUserCommandHandler _handler;
    
    [SetUp]
    public void Setup()
    {
        _mockUserRepository = new Mock<IUserRepository>();
        _mockPasswordService = new Mock<IPasswordHashService>();
        _mockLocalizer = new Mock<IStringLocalizer<SharedResources>>();
        
        _handler = new CreateUserCommandHandler(
            _mockUserRepository.Object,
            _mockPasswordService.Object,
            _mockLocalizer.Object);
    }
    
    [Test]
    public async Task Handle_WithValidCommand_CreatesUserSuccessfully()
    {
        // Arrange
        var command = new CreateUserCommand
        {
            FirstName = "John",
            LastName = "Doe",
            Email = "john@example.com",
            Password = "SecurePass123!"
        };
        
        _mockUserRepository
            .Setup(r => r.GetByEmailAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((User?)null);  // No existing user
        
        _mockPasswordService
            .Setup(s => s.Hash(It.IsAny<string>()))
            .Returns("hashed_password");
        
        // Act
        var result = await _handler.Handle(command, CancellationToken.None);
        
        // Assert
        Assert.That(result.IsSuccess, Is.True);
        Assert.That(result.Data, Is.Not.Null);
        Assert.That(result.Data.FirstName, Is.EqualTo("John"));
        
        // Verify repository was called
        _mockUserRepository.Verify(
            r => r.CreateAsync(It.IsAny<User>(), It.IsAny<CancellationToken>()),
            Times.Once);
    }
    
    [Test]
    public async Task Handle_WithExistingEmail_ReturnsFail()
    {
        // Arrange
        var command = new CreateUserCommand
        {
            FirstName = "John",
            Email = "existing@example.com",
            Password = "SecurePass123!"
        };
        
        _mockUserRepository
            .Setup(r => r.GetByEmailAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new User(/* existing user */));
        
        // Act
        var result = await _handler.Handle(command, CancellationToken.None);
        
        // Assert
        Assert.That(result.IsSuccess, Is.False);
        Assert.That(result.Error.Code, Is.EqualTo(400));
    }
}
```

### Integration Testing

```csharp
[TestFixture]
public class UserApiIntegrationTests : IAsyncLifetime
{
    private WebApplicationFactory<Program> _factory;
    private HttpClient _client;
    private ApplicationDbContext _context;
    
    public async Task InitializeAsync()
    {
        _factory = new WebApplicationFactory<Program>()
            .WithWebHostBuilder(builder =>
            {
                builder.ConfigureServices(services =>
                {
                    // Replace DbContext with in-memory database
                    var descriptor = services.SingleOrDefault(
                        d => d.ServiceType == typeof(DbContextOptions<ApplicationDbContext>));
                    
                    if (descriptor != null)
                        services.Remove(descriptor);
                    
                    services.AddDbContext<ApplicationDbContext>(options =>
                        options.UseInMemoryDatabase("TestDatabase"));
                });
            });
        
        _client = _factory.CreateClient();
        _context = _factory.Services.GetRequiredService<ApplicationDbContext>();
        
        await _context.Database.EnsureCreatedAsync();
    }
    
    public async Task DisposeAsync()
    {
        await _context.Database.EnsureDeletedAsync();
        await _context.DisposeAsync();
        _factory.Dispose();
        _client.Dispose();
    }
    
    [Test]
    public async Task GetUser_WithValidId_ReturnsOk()
    {
        // Arrange
        var user = new User { Id = 1, FirstName = "John", /* ... */ };
        _context.Users.Add(user);
        await _context.SaveChangesAsync();
        
        // Act
        var response = await _client.GetAsync("/api/v1.0/users/1");
        
        // Assert
        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        var content = await response.Content.ReadAsStringAsync();
        var result = JsonSerializer.Deserialize<Result<UserDetailResult>>(content);
        Assert.That(result.IsSuccess, Is.True);
        Assert.That(result.Data.FirstName, Is.EqualTo("John"));
    }
    
    [Test]
    public async Task CreateUser_WithValidData_Returns201Created()
    {
        // Arrange
        var command = new CreateUserCommand
        {
            FirstName = "Jane",
            LastName = "Smith",
            Email = "jane@example.com",
            Password = "SecurePass123!"
        };
        
        var json = JsonSerializer.Serialize(command);
        var content = new StringContent(json, Encoding.UTF8, "application/json");
        
        // Act
        var response = await _client.PostAsync("/api/v1.0/users", content);
        
        // Assert
        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Created));
        Assert.That(response.Headers.Location, Is.Not.Null);
    }
}
```

---

## Architectural Benefits & Trade-offs

### Benefits

#### 1. **Separation of Concerns**

```
? Each layer has single, well-defined responsibility
? Changes in one layer don't ripple through entire system
? Easy to understand: look at specific layer for specific concern

Example: Changing database from SQL Server to PostgreSQL
Before (without Clean Architecture):
  - Database calls scattered throughout application
  - Must update 50+ files
  - High risk of missing references

With Clean Architecture:
  - Only update Infrastructure layer (DbContext, configs)
  - Application and Domain layers unchanged
  - Single point of change for data persistence
```

#### 2. **Testability**

```
? Business logic (handlers, services) tested independently
? No need for real database in unit tests (mock repositories)
? 95%+ code coverage achievable

Example Unit Test:
- No database
- No HTTP requests
- No external services
- Pure logic testing
- Runs in milliseconds
```

#### 3. **Reusability**

```
? Same handler used by multiple API endpoints
? Same domain model across multiple applications
? Cross-cutting behaviors (logging, validation) applied globally

Example: CreateUserCommand
- Used by: REST API POST /users
- Used by: gRPC CreateUserRpc
- Used by: Message queue consumer
- Single implementation, multiple consumption points
```

#### 4. **Maintainability**

```
? New team member can understand feature by following folder structure
? Consistent patterns across all features
? Onboarding time reduced significantly

File structure communicates intent:
Features/
  UserManagement/
    Commands/
      CreateUser/
        CreateUserCommand.cs      ? Request definition
        CreateUserCommandHandler.cs ? Business logic
        CreateUserCommandValidator.cs ? Validation rules
    Queries/
      GetUser/
        GetUserQuery.cs           ? Request
        GetUserQueryHandler.cs    ? Logic
```

#### 5. **Scalability**

```
? Read operations can scale independently from writes
? Caching strategies applied separately for queries/commands
? Database optimization can target read or write model

Example: E-commerce Site
- Heavy reads: Product catalog
  - Cache aggressively
  - Optimize for read performance
  
- Heavy writes: Order processing
  - Optimize for transactional consistency
  - Minimal caching (data freshness critical)
```

### Trade-offs & Limitations

#### 1. **Complexity**

```
? Initial setup requires more files/folders than monolithic architecture
? Learning curve for new team members unfamiliar with Clean Architecture
? More abstractions = more indirection to follow

Example: Simple "Get user" feature
Monolithic:
  - 1 file (UserController + direct DB query)

Clean Architecture:
  - 5+ files (Controller, Query, Handler, Repository, DbContext config)
  
Benefit appears as complexity grows:
  - 10 features: Clean Architecture advantage small
  - 100 features: Monolithic becomes unmaintainable
  - 1000+ features: Clean Architecture essential
```

#### 2. **Performance Overhead**

```
? Additional layers introduce latency
? DI container resolution adds microseconds per request
? Async/await patterns can be harder to debug

Typical overhead:
- Single query: +20-50ms (minimal - mostly database time)
- Heavily trafficked endpoint: May need caching/optimization

Mitigation:
- Redis caching
- Query optimization
- Connection pooling
- Async throughout the stack
```

#### 3. **Over-Engineering Small Projects**

```
? Overkill for simple CRUD applications
? Unnecessary complexity for projects with limited scope

When to avoid Clean Architecture:
- Simple scripts or utilities
- One-off data migrations
- Throwaway prototypes

When to use Clean Architecture:
- Multi-year maintenance expected
- Team size > 3 developers
- Frequent requirements changes
- System evolves significantly over time
```

#### 4. **Learning Curve**

```
? Developers from monolithic backgrounds need education
? CQRS pattern not intuitive for query-command newbies
? More patterns to understand and apply correctly

Mitigation:
- Clear documentation and examples
- Code reviews focusing on patterns
- Standardized project templates
- Team workshops on architecture
```

### Metrics & When to Use Clean Architecture

```
Project Size        Recommendation
????????????????????????????????????????
< 10 features       Use simplified approach (optional layers)
10-50 features      Full Clean Architecture recommended
50+ features        Full Clean Architecture essential
> 1000 features     Essential + possible domain-driven design

Team Size          Recommendation
????????????????????????????????????????
1 person           Monolithic (simpler)
2-3 people         Simplified Clean Architecture
5+ people          Full Clean Architecture + CQRS

Maintenance Period Recommendation
????????????????????????????????????????
< 6 months         Monolithic acceptable
6-24 months        Clean Architecture recommended
> 2 years          Clean Architecture essential
```

---

## Conclusion

### Key Takeaways

1. **Dependency Direction**: Inner layers depend on nothing, outer layers depend inward
2. **CQRS Separation**: Commands modify state, queries read-only
3. **Abstraction Over Concretion**: Program to interfaces, not implementations
4. **Testability First**: Architecture should enable easy testing
5. **Single Responsibility**: Each layer/class has one reason to change
6. **Async Throughout**: Use async/await from API to database
7. **Cross-Cutting Behaviors**: Use MediatR pipeline for logging, validation, transactions

### Implementation Checklist

```
? Project Structure
  ?? Domain (pure business logic, no frameworks)
  ?? Application (use cases, CQRS)
  ?? Infrastructure (data access, external integrations)
  ?? API (HTTP endpoints, middlewares)

? CQRS Setup
  ?? Commands defined with handlers
  ?? Queries defined with handlers
  ?? Validators for commands
  ?? Result<T> wrapper for responses

? Dependency Injection
  ?? All layers registered in DI container
  ?? Service lifetimes configured (Transient/Scoped/Singleton)
  ?? No service locator anti-pattern

? Cross-Cutting Concerns
  ?? Validation behavior
  ?? Logging behavior
  ?? Transaction behavior
  ?? Exception handling middleware

? Testing
  ?? Domain entity tests
  ?? Handler unit tests (with mocks)
  ?? Integration tests (with test database)
  ?? API endpoint tests (WebApplicationFactory)
```

This architecture provides the foundation for building maintainable, scalable, and testable .NET applications. While it requires initial investment in setup and understanding, the long-term benefits in code quality, team productivity, and system stability far outweigh the initial complexity.

