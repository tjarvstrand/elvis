-module(elvis_webhook).

-behaviour(egithub_webhook).

-export([event/1, event/2]).
-export([handle_pull_request/3, handle_error/3]).

-type comment() :: #{file   => string(),
                     number => pos_integer(),
                     text   => binary()
                    }.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%% External Functions

-spec event(egithub_webhook:request()) -> ok | {error, term()}.
event(Request) -> event(github_credentials(), Request).

-spec event(egithub:credentials(), egithub_webhook:request()) ->
  ok | {error, term()}.
event(Cred, Request) -> egithub_webhook:event(?MODULE, Cred, Request).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%% Callbacks

-spec handle_pull_request(
  egithub:credentials(), egithub_webhook:req_data(),
  [egithub_webhook:file()]) ->
  {ok, [egithub_webhook:message()]} | {error, term()}.
handle_pull_request(Cred, Data, GithubFiles) ->
    #{<<"repository">> := Repository} = Data,
    BranchName = maps_get([ <<"pull_request">>,
                            <<"head">>,
                            <<"ref">>],
                            Data, <<"master">>),
    Repo = binary_to_list(maps:get(<<"full_name">>, Repository)),
    Branch = binary_to_list(BranchName),
    Config = repo_config(Cred, Repo, Branch, elvis_config:default()),

    GithubFiles1 = [F#{path => Path}
                    || F = #{<<"filename">> := Path} <- GithubFiles],
    Config1 = elvis_config:resolve_files(Config, GithubFiles1),

    FileInfoFun = fun (File) -> file_info(Cred, Repo, File) end,
    Config2 = elvis_config:apply_to_files(FileInfoFun, Config1),

    case elvis_core:rock(Config2) of
        {fail, Results} -> {ok, messages_from_results(Results)};
        ok -> {ok, []}
    end.

-spec handle_error( {error, term()}
                  , egithub_webhook:req_data()
                  , [egithub_webhook:file()]) ->
  {error, {failed, integer()}, string()} | {ok, [map()], string()}.
handle_error(Error, ReqData, GithubFiles) ->
  #{ <<"repository">> := Repository
   , <<"number">> := Number
   } = ReqData,
  #{<<"full_name">> := RepoName} = Repository,

  {Output, ExitStatus} =
    case Error of
      {badmatch, {error, {Status, Out, _}}} -> {Out, Status};
      {error, {status, Status, Out}} -> {Out, Status};
      FullErr -> {FullErr, 1}
    end,

  catch_error_source( io_lib:format("~p", [Output])
                    , ExitStatus
                    , GithubFiles
                    , RepoName
                    , Number
                    ).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%% Catch error Functions

-spec catch_error_source(Output::string(),
                         ExitStatus::integer(),
                         GithubFiles::[egithub_webhook:file()],
                         RepoName::string(),
                         Number::integer()) ->
  {error, {failed, integer()}, string()} |
  {ok, [map()], string()}.
catch_error_source(Output, ExitStatus, GithubFiles, RepoName, Number) ->
  Lines = output_to_lines(Output),
  Comments = extract_errors(Lines),
  Messages = messages_from_comments(Comments, GithubFiles),
  report_error(Messages, RepoName, ExitStatus, Output, Number).

-spec output_to_lines(Output::string()) ->
  [iodata() | unicode:charlist()].
output_to_lines(Output) ->
  DecodedOutput = unicode:characters_to_binary(Output),
  try
    re:split(DecodedOutput, "\n", [{return, binary}, trim])
  catch
    _:Error ->
      _ = lager:warning("Uncomprehensible output: ~p", [DecodedOutput]),
      Error
  end.

-spec extract_errors(Lines ::[list()]) -> [map()].
extract_errors(Lines) ->
  {ok, Regex} = re:compile(<<"(.+):([0-9]*): (.+)">>),
  extract_errors(Lines, Regex, []).
extract_errors([], _Regex, Errors) -> Errors;
extract_errors([Line|Lines], Regex, Errors) ->
  NewErrors =
    case re:run(Line, Regex, [{capture, all_but_first, binary}]) of
      {match, [File, <<>>, Comment]} ->
        [#{ file   => File
          , number => 0
          , text   => Comment
          } | Errors];
      {match, [File, Number, Comment]} ->
        [#{ file   => File
          , number => binary_to_integer(Number)
          , text   => Comment
          } | Errors];
      {match, Something} ->
        _ = lager:error("WHAT? ~p", [Something]),
        [];
      _ ->
        Errors
    end,
  extract_errors(Lines, Regex, NewErrors).

-spec messages_from_comments([comment()], [egithub_webhook:file()]) ->
  [egithub_webhook:message()].
messages_from_comments(Comments, GithubFiles) ->
  lists:flatmap(
    fun(Comment) ->
      messages_from_comment(Comment, GithubFiles)
    end, Comments).

messages_from_comment(#{file := <<>>} = Comment, GithubFiles) ->
  #{text := Text} = Comment,
  [#{<<"filename">> := FileName} = FirstFile|_] = GithubFiles,
  FullText = format_message(Text),
  messages_from_comment(FileName, 0, FullText, FirstFile);
messages_from_comment(Comment, GithubFiles) ->
  #{ file   := File
   , number := Line
   , text   := Text
   } = Comment,
  MatchingFiles =
    [GithubFile
     || #{ <<"filename">>  := FileName
         , <<"status">>    := Status
         } = GithubFile <- GithubFiles
          , true == ends_with(File, FileName)
          , Status /= <<"deleted">>
    ],
  case MatchingFiles of
    [] -> [];
    [MatchingFile|_] ->
      FullText = format_message(Text),
      #{<<"filename">> := FileName} = MatchingFile,
      messages_from_comment(FileName, Line, FullText, MatchingFile)
  end.

ends_with(Big, Small) when is_list(Big) ->
  BigBinary = list_to_binary(Big),
  ends_with(BigBinary, Small);
ends_with(Big, Small) when is_list(Small) ->
  SmallBinary = list_to_binary(Small),
  ends_with(Big, SmallBinary);
ends_with(Big, Small) ->
  LBig = erlang:size(Big),
  LSmall = erlang:size(Small),
  LRest = LBig - LSmall,
  case Big of
    <<_:LRest/binary, Small/binary>> -> true;
    _Other -> false
  end.

messages_from_comment(Filename, 0, Text, File) ->
  #{<<"raw_url">> := RawUrl} = File,
  [ #{commit_id => commit_id_from_raw_url(RawUrl, Filename),
      path      => Filename,
      position  => 0,
      text      => Text
     }
  ];
messages_from_comment(Filename,
                      Line,
                      Text,
                      #{<<"patch">> := Patch, <<"raw_url">> := RawUrl}) ->
  case elvis_git:relative_position(Patch, Line) of
    {ok, Position} ->
      [ #{commit_id => commit_id_from_raw_url(RawUrl, Filename),
          path      => Filename,
          position  => Position,
          text      => Text
         }
      ];
    not_found ->
      _ = lager:info("Line ~p does not belong to file's diff.", [Line]),
      []
  end;
messages_from_comment(Filename, _Line, Text, File) ->
  messages_from_comment(Filename, 0, Text, File).

-spec format_message(iodata()) -> binary().
format_message(Text) ->
  iolist_to_binary(["According to **Elvis**:\n> ", Text]).

-spec report_error(list(), string(), integer(), string(), integer()) ->
  {error, {failed, integer()}, string()} | {ok, [map()], string()}.
report_error([], Repo, ExitStatus, Lines, Number) ->
  DetailsUrl = save_status_log(Lines, Repo, Number),
  {error, {failed, ExitStatus}, DetailsUrl};
report_error( [#{commit_id := CommitId} | _] = Messages, Repo, ExitStatus
            , Lines, Number) ->
  Text = io_lib:format( "**Elvis** failed with exit status: ~p", [ExitStatus]),
  ExtraMessage =
    #{commit_id => CommitId,
      path      => "",
      position  => 0,
      text      => list_to_binary(Text)
     },
  DetailsUrl = save_status_log(Lines, Repo, Number),
  {ok, [ExtraMessage | Messages], DetailsUrl}.

-spec status_details_url(integer(), integer()) -> string().
status_details_url(PrNumber, Id) ->
  % It has to bo added in elvis_server
  {ok, StatusDetailsUrl} = application:get_env(elvis, status_details_url),
  lists:flatten(
      io_lib:format("~s~p/~p/~p", [StatusDetailsUrl, PrNumber, elvis, Id])).

-spec save_status_log(string(), string(), integer()) -> string().
save_status_log(Lines, Repo, PrNumber) ->
  % elvis_logs entity has to bo added in elvis_server
  Log = elvis_logs_repo:create(Repo, PrNumber, Lines),
  Id = elvis_logs:id(Log),
  status_details_url(PrNumber, Id).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%% Helper functions

-spec github_credentials() -> egithub:credentials().
github_credentials() ->
    User = application:get_env(elvis, github_user, ""),
    Password = application:get_env(elvis, github_password, ""),
    egithub:basic_auth(User, Password).

file_info(Cred, Repo,
          #{<<"filename">> := Filename,
            <<"raw_url">> := RawUrl,
            <<"patch">> := Patch}) ->
    CommitId = commit_id_from_raw_url(RawUrl, Filename),
    {ok, Content} = egithub:file_content(Cred, Repo, CommitId, Filename),
    #{path => Filename,
      content => Content,
      commit_id => CommitId,
      patch => Patch}.

repo_config(Cred, Repo, Branch, LocalConfig) ->
    case egithub:file_content(Cred, Repo, Branch, "elvis.config") of
        {ok, ConfigContent} ->
            ConfigEval = ktn_code:eval(ConfigContent),
            elvis_config:load(ConfigEval);
        {error, _} ->
            LocalConfig
    end.

%% @doc Gets a raw_url for a file and extracts the commit id from it.
-spec commit_id_from_raw_url(string(), string()) -> string().
commit_id_from_raw_url(Url, Filename) ->
    UrlString = elvis_utils:to_str(Url),
    Regex = ".+/raw/(.+)/" ++ Filename,
    {match, [_, {Pos, Len} | _]} = re:run(UrlString, Regex),
    string:substr(UrlString, Pos + 1, Len).

messages_from_results(Results) ->
    lists:flatmap(
        fun(Result) ->
            messages_from_result(Result)
        end, Results).

messages_from_result(Result) ->
    File = elvis_result:get_file(Result),
    Rules = elvis_result:get_rules(Result),
    lists:flatmap(
        fun(Rule) ->
            messages_from_result(Rule, File)
        end, Rules).

messages_from_result(Rule, File) ->
    Items = elvis_result:get_items(Rule),
    lists:flatmap(
        fun(Item) ->
            messages_from_item(Item, File)
        end, Items).

messages_from_item(Item, File) ->
    #{path := Path,
      commit_id := CommitId,
      patch := Patch} = File,
    Message = elvis_result:get_message(Item),
    Info = elvis_result:get_info(Item),
    Line = elvis_result:get_line_num(Item),
    Text = list_to_binary(io_lib:format(Message, Info)),

    case Line of
        0 ->
            [#{text => Text,
               position => Line}];
        _ ->
            case elvis_git:relative_position(Patch, Line) of
                {ok, Position} ->
                    [ #{commit_id => CommitId,
                        path      => Path,
                        position  => Position,
                        text      => Text
                       }
                    ];
                not_found ->
                    Args = [Line],
                    ok =
                        error_logger:info_msg(
                            "Line ~p does not belong to file's diff.", Args),
                    []
            end
    end.

maps_get([Key], Map, Default) -> maps:get(Key, Map, Default);
maps_get([Key | Rest], Map, Default) ->
    case maps:get(Key, Map, Default) of
        NewMap when is_map(NewMap) ->
            maps_get(Rest, NewMap, Default);
        _ ->
            Default
    end.